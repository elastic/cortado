# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


# testing DLL that will spawn notepad once DllMain is invoked
DLL = "bin/faultrep.dll"

# we will copy WerFault.exe to temp to sideload our testing DLL faultrep.dll
WER = "c:\\windows\\system32\\werfault.exe"


@register_code_rta(
    id="ec52377c-b2a8-4c44-8eb4-465376f2189a",
    name="evasion_oversized_dll_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="33cdad6c-5809-4d78-94f0-5a5153289e7e", name="Oversized DLL Creation followed by SideLoad"),
        RuleMetadata(id="65a402ff-904b-4d14-b7aa-fa0c5ae575f8", name="Potential Evasion via Oversized Image Load"),
        RuleMetadata(
            id="b58a6662-cc72-4c1c-a24e-703427f3b725", name="Rundll32 or Regsvr32 Executing an OverSized File"
        ),
        RuleMetadata(
            id="d84090d7-91e4-4063-84c1-c1f410dd717b", name="DLL Side Loading via a Copied Microsoft Executable"
        ),
        RuleMetadata(id="901f0c30-a7c5-40a5-80e3-a50c6744632f", name="RunDLL32/Regsvr32 Loads Dropped Executable"),
    ],
    techniques=["T1027", "T1574"],
)
def main():
    import win32file  # type: ignore

    if Path(DLL).is_file():
        tempc = os.path.expandvars("%localappdata%\\Temp\\oversized.dll")
        rta_dll = os.path.expandvars("%localappdata%\\Temp\\faultrep.dll")
        rta_pe = os.path.expandvars("%localappdata%\\Temp\\wer.exe")
        # copy files to temp
        win32file.CopyFile(DLL, tempc, 0)  # type: ignore
        win32file.CopyFile(WER, rta_pe, 0)  # type: ignore
        if Path(tempc).is_file():
            log.info(f"{DLL} copied to {tempc}")
        log.info(f"File {tempc} will be appended with null bytes to reach 90MB in size.")
        # append null bytes to makde the DLL oversized 90+MB in size
        with open(tempc, "rb+") as binfile:
            _ = binfile.seek(100000000)
            _ = binfile.write(b"\x00")

        # copied via cmd to trigger the rule - python is signed and won't trigger the file mod part of the rule
        _ = _common.execute_command(["cmd.exe", "/c", "copy", tempc, rta_dll])
        if Path(rta_dll).is_file() and Path(rta_pe).is_file():
            # should trigger rundll32 rules
            _ = _common.execute_command(["rundll32.exe", rta_dll, "DllMain"])
            # should trigger dll sideload from current dir
            _ = _common.execute_command([rta_pe])
        # cleanup
        _ = _common.execute_command(["taskkill", "/f", "/im", "notepad.exe"])
        log.info("Cleanup.")
        win32file.DeleteFile(tempc)
        win32file.DeleteFile(rta_dll)
        win32file.DeleteFile(rta_pe)
        log.info("RTA Done!")
