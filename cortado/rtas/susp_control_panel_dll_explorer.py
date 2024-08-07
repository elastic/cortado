# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="91238171-b3f1-4c0b-80bb-90a824e2ed61",
    name="susp_control_panel_dll_explorer",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="1dbf6ac3-540a-4214-8173-9aa93232da38", name="Suspicious Control Panel DLL Loaded by Explorer")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    explorer = "C:\\Users\\Public\\explorer.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\rta.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, explorer)

    _common.log("Modifying the OriginalFileName attribute to invalidate the signature")
    _common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "rta.dll"])

    _common.log("Loading rta.dll")
    _common.execute(
        [
            explorer,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll}; echo",
            "/factory,{5BD95610-9434-43C2-886C-57852CC8A120}",
            ";powershell",
        ],
        timeout=10,
    )
    _common.remove_files(dll, ps1, rcedit, explorer)
