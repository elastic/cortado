# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="7cc740ff-2e6c-4740-9323-46dcbb4dbfbc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7c0048d5-356d-4f69-839e-10c1e194958f", name="UAC Bypass via ComputerDefaults Execution Hijack")
    ],
    siem_rules=[],
    techniques=["T1548"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    key = "Software\\Classes\\ms-settings\\shell\\open\\command"
    value = "test"
    data = "test"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass

    computerdefaults = "C:\\Users\\Public\\ComputerDefaults.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, computerdefaults)

    _common.execute([computerdefaults, "/c", powershell], timeout=2, kill=True)
    _common.remove_file(computerdefaults)
