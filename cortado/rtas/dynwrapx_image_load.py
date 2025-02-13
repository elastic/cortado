# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d8de8c03-d5d0-4118-8971-32439638d69f",
    name="dynwrapx_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="4cd6f758-0057-4e8a-9701-20b6116c2118", name="Dynwrapx Image Load via Windows Scripts"),
        RuleMetadata(
            id="83da4fac-563a-4af8-8f32-5a3797a9068e", name="Suspicious Windows Script Interpreter Child Process"
        ),
    ],
    techniques=["T1055", "T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    RENAMER = _common.get_resource_path("bin/rcedit-x64.exe")

    cscript = "C:\\Users\\Public\\cscript.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\dynwrapx.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, cscript)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "dynwrapx.dll"])

    log.info("Loading dynwrapx.dll into fake cscript")
    _ = _common.execute_command([cscript, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)

    # No idea on why, but after a lot of headaches, I discovered that the dll.pe.original_file_name
    # is only populated if I delay the removal of the dll file
    time.sleep(5)
    _common.remove_files([cscript, dll, ps1, rcedit])
