# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9cca3284-848f-483a-9241-48562eee0605",
    name="image_load_taskhost",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4b4ba027-151f-40e4-99ba-a386735c27e4", name="Unsigned DLL Loaded by Windows Tasks Host")
    ],
    techniques=["T1053", "T1053.005"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    RENAMER = _common.get_resource_path("bin/rcedit-x64.exe")

    taskhost1 = "C:\\Users\\Public\\taskhost1.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(user32, dll)
    _common.copy_file(EXE_FILE, taskhost1)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.dll"])

    log.info("Loading unsigned DLL into fake taskhost")
    _ = _common.execute_command([taskhost1, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)

    _common.remove_files([dll, ps1, rcedit])
