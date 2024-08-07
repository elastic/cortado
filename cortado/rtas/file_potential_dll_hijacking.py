# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
from pathlib import Path




@register_code_rta(
    id="7e23fa7b-1812-4abb-ab42-a2350c9a4741",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': 'ddc4fa22-4675-44c0-a813-e786e638d7e0',
        'rule_name': 'Potential Initial Access via DLL Search Order Hijacking'
    }],
    siem_rules=[],
    techniques=[""],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    appdata = os.getenv("LOCALAPPDATA")
    path = Path(appdata) / "\\Microsoft\\OneDrive"
    winword = "C:\\Users\\Public\\winword.exe"
    dll = path / "\\a.dll"
    _common.copy_file(EXE_FILE, winword)

    if path.is_dir():
        _common.execute([winword, "-c", f"New-Item -Path {dll} -Type File"], timeout=10)
        _common.remove_files(dll, winword)
    else:
        path.mkdir()
        _common.execute([winword, "-c", f"New-Item -Path {dll} -Type File"], timeout=10)
        _common.remove_files(dll, winword)
        path.rmdir()


