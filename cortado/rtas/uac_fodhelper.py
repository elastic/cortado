# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="a67586fd-cceb-4fb9-bf0e-d355b9e8921a",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b5c0058e-2bca-4ed5-84b3-4e017c039c57", name="UAC Bypass via FodHelper Execution Hijack")
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

    fodhelper = "C:\\Users\\Public\\fodhelper.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, fodhelper)

    _common.execute([fodhelper, "/c", powershell], timeout=2, kill=True)
    _common.remove_file(fodhelper)
