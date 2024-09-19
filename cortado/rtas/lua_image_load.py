# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="860e5968-c31f-4928-ac05-3c3c2d19450c",
    name="lua_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="8f237d98-1825-4c27-a5cd-e38bde70882a", name="Suspicious Windows LUA Script Execution")
    ],
    siem_rules=[],
    techniques=["T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    RENAMER = _common.get_resource_path("bin/rcedit-x64.exe")

    posh = "C:\\Users\\Public\\posh.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\luacom.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, posh)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    # Modify the originalfilename to invalidate the code sig
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.exe"])

    log.info("Loading luacom.dll into fake posh")
    _ = _common.execute_command(
        [
            posh,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll};",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "445",
        ],
        timeout_secs=10,
    )

    _common.remove_files([posh, dll, ps1, rcedit])
