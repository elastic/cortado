# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path



@register_code_rta(
    id="3c40b5fd-afd0-4794-8af3-f7af249edf84",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '397945f3-d39a-4e6f-8bcb-9656c2031438', 'rule_name': 'Persistence via Microsoft Outlook VBA'}],
    techniques=['T1137'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Outlook"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\VbaProject.OTM"
    _common.copy_file(EXE_FILE, file)

    _common.remove_files(file)


