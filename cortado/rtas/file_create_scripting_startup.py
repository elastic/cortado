# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path



@register_code_rta(
    id="e56f77bc-d9a7-4e02-97e2-b3056f3d4171",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '440e2db4-bc7f-4c96-a068-65b78da59bde',
        'rule_name': 'Startup Persistence by a Suspicious Process'
    }],
    techniques=['T1547', 'T1547.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    argpath = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\'Start Menu'\\Programs\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = argpath + "\\file.exe"

    _common.execute([powershell, "/c", f"echo AAAAAAAA | Out-File {file}"], timeout=10, kill=True)
    _common.remove_files(file)


