# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="cd549ba9-63be-4eff-ab6c-f567445e1977",
    name="msxsl_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="de3615bc-4e50-485e-b3b5-8548ef6faa3d", name="Script Execution via MSXSL"),
    ],
    siem_rules=[],
    techniques=["T1220", "T1218", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    RENAMER = _common.get_resource_path("bin/rcedit-x64.exe")

    msxsl = "C:\\Users\\Public\\msxsl.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\scrobj.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, msxsl)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, msxsl, "--set-version-string", "OriginalFilename", "msxsl.exe"])

    log.info("Loading scrobj.dll into fake msxsl")
    _ = _common.execute_command([msxsl, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)

    _common.remove_files([msxsl, dll, ps1, rcedit])
