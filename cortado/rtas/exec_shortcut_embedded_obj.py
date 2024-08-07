# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="32faebaa-b581-464c-bca9-6936fe0948dc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            'rule_id': '8076640d-ec66-4d24-a252-ee2f054e00a1',
            'rule_name': 'Windows Shortcut File Embedded Object Execution'
        },
        {
            'rule_id': '9fdd772b-b483-404f-bc02-7ec87e332bec',
            'rule_name': 'Embedded Executable via Windows Shortcut File'
        }
    ],
    siem_rules=[],
    techniques=['T1059', 'T1059.003', 'T1204', 'T1204.001', 'T1204.002', 'T1566', 'T1566.001', 'T1566.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(_common.WINDOWS)
def main():
    cmd = "C:\\Users\\Public\\cmd.exe"
    rta = "C:\\Users\\Public\\rta.exe"
    tempfile = "C:\\Users\\Public\\a.txt"
    _common.copy_file(EXE_FILE, cmd)
    _common.copy_file(EXE_FILE, rta)

    # Execute command
    _common.execute([cmd, "/c", f"Copy-Item {EXE_FILE} '{tempfile}'; echo 'finda.a.lnk >1&'; {rta}"],
                   kill=True, timeout=10)
    _common.remove_files(cmd, rta, tempfile)


if __name__ == "__main__":
    exit(main())
