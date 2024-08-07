# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="83332fb4-2299-4584-b5f3-7e0264d034f7",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '2c3c29a4-f170-42f8-a3d8-2ceebc18eb6a',
        'rule_name': 'Suspicious Microsoft Diagnostics Wizard Execution'
    }],
    techniques=['T1218'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")



def main():
    msdt = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, msdt)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, msdt, "--set-version-string", "OriginalFilename", "msdt.exe"])

    _common.execute([msdt], timeout=2, kill=True)

    _common.remove_files(rcedit, msdt)


if __name__ == "__main__":
    exit(main())
