# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="bbad34f5-3542-4484-9b23-5ef05af94c0f",
    name="exec_dll_file_compressed",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="08fba401-b76f-4c7b-9a88-4f3b17fe00c1", name="DLL Loaded from an Archive File")],
    techniques=["T1204", "T1204.002", "T1574", "T1574.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    path = "C:\\Users\\Public\\Temp\\7z\\"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = "C:\\Users\\Public\\Temp\\7z\\file.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\Temp\\7z\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    _common.copy_file(user32, dll)
    _common.copy_file(EXE_FILE, file)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    log.info("Modifying the OriginalFileName attribute to invalidate the signature")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.dll"])

    log.info("Loading unsigned DLL into fake taskhost")
    _ = _common.execute_command([file, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)

    _common.remove_files([dll, ps1, rcedit, file])
