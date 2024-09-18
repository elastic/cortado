# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="aa6bf766-db74-4db5-8eec-f91386b1285b",
    name="cmstp_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="8adfa9ad-0ed2-4b1b-bdad-f2c52e1d2a00", name="Scriptlet Execution via CMSTP"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    cmstp = "C:\\Users\\Public\\cmstp.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\scrobj.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, cmstp)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, cmstp, "--set-version-string", "OriginalFilename", "CMSTP.EXE"])

    log.info("Loading scrobj.dll into fake cmstp")
    _ = _common.execute_command([cmstp, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)

    _common.remove_files([cmstp, dll, ps1, rcedit])
