# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path



@register_code_rta(
    id="edb804d6-85df-4dca-a521-1b6dfee9f354",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': '7df7fca3-8a91-4a54-9799-0478a90ae326',
        'rule_name': 'Suspicious Browser Files Modification'
    }],
    siem_rules=[],
    techniques=['T1176', 'T1112'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    proc = "C:\\Users\\Public\\proc.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Mozilla\\Test\\Profiles\\AdefaultA"
    file = path + "\\extensions.json"
    _common.copy_file(EXE_FILE, proc)
    Path(path).mkdir(parents=True, exist_ok=True)

    _common.execute([proc, "/c", f"Copy-Item {EXE_FILE} {file}"], timeout=10)
    _common.remove_files(proc, file)


if __name__ == "__main__":
    exit(main())
