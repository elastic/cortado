# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="83332fb4-2299-4584-b5f3-7e0264d034f7",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="2c3c29a4-f170-42f8-a3d8-2ceebc18eb6a", name="Suspicious Microsoft Diagnostics Wizard Execution"
        )
    ],
    techniques=["T1218"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    msdt = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, msdt)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, msdt, "--set-version-string", "OriginalFilename", "msdt.exe"])

    _common.execute([msdt], timeout=2, kill=True)

    _common.remove_files(rcedit, msdt)
