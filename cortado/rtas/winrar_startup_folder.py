# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: WinRAR Startup Folder
# RTA: winrar_startup_folder.py
# ATT&CK: T1060
# Description: Writes batch file into Windows Startup folder using process ancestry tied to exploit (CVE-2018-20250)

import os
from pathlib import Path


@register_code_rta(
    id="6d2d3c21-2d71-4395-8ab7-b1d0138d9225",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=[],
)
def main():
    _common.log("WinRAR StartUp Folder Persistence")
    win_rar_path = Path("WinRAR.exe").resolve()
    ace_loader_path = Path("Ace32Loader.exe").resolve()
    batch_file_path = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\mssconf.bat"
    startup_path = os.environ["USERPROFILE"] + batch_file_path
    _common.copy_file("C:\\Windows\\System32\\cmd.exe", win_rar_path)
    _common.copy_file("C:\\Windows\\System32\\cmd.exe", ace_loader_path)
    _common.execute(
        [win_rar_path, "/c", ace_loader_path, "/c", "echo", "test", "^>", startup_path],
        kill=True,
    )
    _common.remove_file(startup_path)
    _common.remove_file(ace_loader_path)
    _common.remove_file(win_rar_path)


if __name__ == "__main__":
    exit(main())
