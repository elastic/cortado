# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="2cefb7c2-5ffc-4410-a63c-bded93b258c3",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            'rule_id': '877c6bd9-8df1-4a15-aa97-2a091731b15d',
            'rule_name': 'Suspicious MsiExec Child Process'
        },
        {'rule_id': '16c84e67-e5e7-44ff-aefa-4d771bcafc0c', 'rule_name': 'Execution from Unusual Directory'},
        {'rule_id': '35dedf0c-8db6-4d70-b2dc-a133b808211f', 'rule_name': 'Binary Masquerading via Untrusted Path'},
        {'rule_id': '5db08297-bf72-49f4-b426-f405c2b01326', 'rule_name': 'Regsvr32 with Unusual Arguments'}
    ],
    siem_rules=[],
    techniques=['T1218', 'T1218.007'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    msiexec = "C:\\Users\\Public\\msiexec.exe"
    regsvr32 = "C:\\Users\\Public\\regsvr32.exe"
    _common.copy_file(EXE_FILE, msiexec)
    _common.copy_file(EXE_FILE, regsvr32)

    _common.execute([msiexec, "/c", regsvr32, "echo", "scrobj.dll"], timeout=5, kill=True)
    _common.remove_files(msiexec)


if __name__ == "__main__":
    exit(main())
