# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path



@register_code_rta(
    id="97979b30-908d-4c57-a33a-f3b78e55a84a",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': 'aaa80718-1ed9-43bd-bcf7-97f2a6c93ea8',
        'rule_name': 'Persistence via Microsoft Office AddIns'
    }],
    siem_rules=[],
    techniques=['T1137'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Word\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\file.exe"

    _common.copy_file(EXE_FILE, file)
    _common.remove_file(file)


