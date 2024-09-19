# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: WinRAR Startup Folder
# RTA: winrar_startup_folder.py
# ATT&CK: T1060
# Description: Writes batch file into Windows Startup folder using process ancestry tied to exploit (CVE-2018-20250)

import logging
import os
from pathlib import Path

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6d2d3c21-2d71-4395-8ab7-b1d0138d9225",
    name="winrar_startup_folder",
    platforms=[OSType.WINDOWS],
)
def main():
    log.info("WinRAR StartUp Folder Persistence")
    win_rar_path = Path("WinRAR.exe").resolve()
    ace_loader_path = Path("Ace32Loader.exe").resolve()
    batch_file_path = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\mssconf.bat"
    startup_path = os.environ["USERPROFILE"] + batch_file_path
    _common.copy_file("C:\\Windows\\System32\\cmd.exe", win_rar_path)
    _common.copy_file("C:\\Windows\\System32\\cmd.exe", ace_loader_path)
    _ = _common.execute_command(
        [str(win_rar_path), "/c", str(ace_loader_path), "/c", "echo", "test", "^>", str(startup_path)],
    )
    _common.remove_file(startup_path)
    _common.remove_file(ace_loader_path)
    _common.remove_file(win_rar_path)
