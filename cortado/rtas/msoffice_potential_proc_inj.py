# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="afaf4f08-765e-4d4a-8db0-5a2613e1f5be",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            'rule_id': '05599d18-6ff7-4fff-ad2d-f03c930a7b6e',
            'rule_name': 'Potential Process Injection from Malicious Document'
        }
    ],
    siem_rules=[],
    techniques=['T1055', 'T1566', 'T1566.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    winword = "C:\\Users\\Public\\winword.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    _common.copy_file(EXE_FILE, winword)

    _common.execute([winword, "/c", cmd], timeout=5, kill=True)
    _common.remove_files(winword)


if __name__ == "__main__":
    exit(main())
