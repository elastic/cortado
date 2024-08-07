# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path



@register_code_rta(
    id="b8dcb997-e099-472e-8f2f-15a80c8dfe1a",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            'rule_id': 'dec8781c-ef73-4037-9684-ef28c0322fa4',
            'rule_name': 'Script File Written to Startup Folder'
        },
        {
            "rule_name": "Unusual File Written or Modified in Startup Folder",
            "rule_id": "30a90136-7831-41c3-a2aa-1a303c1186ac",
        }
    ],
    siem_rules=[],
    techniques=['T1547', 'T1547.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    proc = "C:\\Users\\Public\\proc.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\'Start Menu'\\Programs\\Startup\\"
    file = path + "\\a.js"
    _common.copy_file(EXE_FILE, proc)
    Path(path).mkdir(parents=True, exist_ok=True)

    _common.execute([proc, "/c", f"Copy-Item {EXE_FILE} {file}"], timeout=10)
    _common.remove_files(proc, file)


