# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2145af1a-0781-47ab-8d73-2d50e93b5ff7",
    name="image_load_vaultcli",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="048737fe-80d6-4462-aa80-ffeed853103e", name="Suspicious Vault Client Image Load")],
)
def main():
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    RENAMER = _common.get_resource_path("bin/rcedit-x64.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\vaultcli.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "vaultcli.dll"])

    log.info("Loading System.DirectoryServices.Protocols.test.dll")
    _ = _common.execute_command([powershell, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)

    _common.remove_files([dll, ps1, rcedit])
