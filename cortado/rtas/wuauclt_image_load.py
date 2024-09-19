# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="42eed432-af05-45d3-b788-7e3220f81f9a",
    name="wuauclt_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="3788c03d-28a5-4466-b157-d6dd4dc449bb", name="Suspicious ImageLoad via Windows Update Auto Update Client"
        )
    ],
    siem_rules=[],
    techniques=["T1218"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")
    ps1_file = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    renamer = _common.get_resource_path("bin/rcedit-x64.exe")

    wuauclt = "C:\\Users\\Public\\wuauclt.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(exe_file, wuauclt)
    _common.copy_file(user32, dll)
    _common.copy_file(ps1_file, ps1)
    _common.copy_file(renamer, rcedit)

    # Modify the originalfilename to invalidate the code sig
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.exe"])

    log.info("Loading unsigned.dll into fake wuauclt")
    _ = _common.execute_command(
        [
            wuauclt,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll}",
            ";echo",
            "/RunHandlerComServer",
            ";echo",
            "/UpdateDeploymentProvider",
        ],
        timeout_secs=10,
    )

    _common.remove_files([wuauclt, dll, ps1, rcedit])
