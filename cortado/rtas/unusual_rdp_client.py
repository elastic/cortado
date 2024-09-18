# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d3c0c965-3167-4fe3-8aee-a9f101766b5a",
    name="unusual_rdp_client",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="d448566e-486f-4b61-a76f-945662313d49", name="Unusual Remote Desktop Client Process")
    ],
    siem_rules=[],
    techniques=["T1021"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    posh = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\posh.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\mstscax.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    _common.copy_file(user32, dll)
    _common.copy_file(powershell, posh)
    _common.copy_file(PS1_FILE, ps1)

    log.info("Loading mstscax.dll into posh")
    _ = _common.execute_command(
        [
            posh,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll};",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "3389",
        ],
        timeout_secs=10,
    )
    _common.remove_files([dll, ps1, posh])
