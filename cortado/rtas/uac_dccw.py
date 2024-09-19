# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="cfb116f0-ad83-4d77-803f-064c2cfd93fe",
    name="uac_dccw",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="18a26e3e-e535-4d23-8ffa-a3cdba56d16e", name="Suspicious Parent-Child Relationship"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="093bd845-b59f-4868-a7dd-62d48b737bf6", name="UAC Bypass Attempt via DCCW DLL Search Order Hijacking"
        ),
    ],
    siem_rules=[],
    techniques=["T1129", "T1548", "T1036", "T1055", "T1574"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    dccw = "C:\\Users\\Public\\dccw.exe"
    dllhost = "C:\\Users\\Public\\dllhost.exe"
    dccwpath = "C:\\Users\\Public\\dccw.exe.test"
    dccwpathdll = "C:\\Users\\Public\\dccw.exe.test\\a.dll"
    dccwpathdll2 = "C:\\Users\\Public\\dccw.exe.test\\b.dll"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, dccw)
    _common.copy_file(EXE_FILE, dllhost)

    # Create Dir
    _ = _common.execute_command([powershell, "/c", f"New-Item -Path {dccwpath} -Type Directory"], timeout_secs=10)
    _common.copy_file(EXE_FILE, dccwpathdll)
    _ = _common.execute_command([dllhost, "/c", f"Rename-Item {dccwpathdll} {dccwpathdll2}"], timeout_secs=10)
    _ = _common.execute_command([dccw, "/c", powershell], timeout_secs=2)
    _common.remove_files([dccw, dllhost, dccwpathdll2])
    _ = _common.execute_command([powershell, "/c", f"rmdir {dccwpath} -Force"], timeout_secs=3)
