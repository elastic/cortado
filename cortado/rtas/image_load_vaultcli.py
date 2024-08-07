# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="2145af1a-0781-47ab-8d73-2d50e93b5ff7",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="048737fe-80d6-4462-aa80-ffeed853103e", name="Suspicious Vault Client Image Load")],
    siem_rules=[],
    techniques=[""],
)
def main():
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\vaultcli.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "vaultcli.dll"])

    _common.log("Loading System.DirectoryServices.Protocols.test.dll")
    _common.execute([powershell, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    _common.remove_files(dll, ps1, rcedit)
