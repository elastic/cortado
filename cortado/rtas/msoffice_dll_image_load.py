# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4ad6b308-f457-4805-89b9-43b99e32b24f",
    name="msoffice_dll_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="a0a82ad6-98ed-4426-abd8-52e7b052e297", name="Microsoft Office Loaded a Dropped Executable File"
        )
    ],
    techniques=["T1566"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")
    ps1_file = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")

    winword = "C:\\Users\\Public\\winword.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\a.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    _common.copy_file(exe_file, winword)
    _common.copy_file(ps1_file, ps1)

    log.info("Droping and Loading a.dll into fake winword")
    _ = _common.execute_command(
        [
            winword,
            "-c",
            f"Copy-Item {user32} {dll}; Import-Module {ps1}; Invoke-ImageLoad {dll}",
        ],
        timeout_secs=10,
    )

    _common.remove_files([winword, dll, ps1])
