# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ab957b94-2c39-49dd-93cf-f1e40394ff1b",
    name="uac_wow64log",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="28a39a43-e850-4941-8605-ffa23dcfd25a", name="UAC Bypass Attempt via WOW64 Logger DLL Side-Loading"
        )
    ],
    techniques=["T1574", "T1548"],
)
def main():
    ps1_file = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    renamer = _common.get_resource_path("bin/rcedit-x64.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wow64log.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(user32, dll)
    _common.copy_file(ps1_file, ps1)
    _common.copy_file(renamer, rcedit)

    log.info("Modifying the OriginalFileName attribute to invalidate the signature")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "wow64log.dll"])

    log.info("Loading wow64log.dll and spawning a high integrity process")
    _ = _common.execute_command(
        [powershell, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}; powershell"],
        timeout_secs=10,
    )

    _common.remove_files([dll, ps1, rcedit])
