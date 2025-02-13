# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="78e59247-db65-412a-898c-2e757d695851",
    name="unusual_kerberos_client",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="9ba39516-651e-489f-8b6a-f5501e0c492d", name="Execution from Suspicious Directory"),
        RuleMetadata(
            id="8d11d741-7a06-41a1-a525-feaaa07ebbae",
            name="Executable File Creation Followed by Immediate Network Connection",
        ),
        RuleMetadata(id="b5c91c3e-9d2d-4df6-afb7-c9d236b5ebe2", name="Unusual Kerberos Client Process"),
    ],
    techniques=["T1558", "T1204", "T1036"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")
    ps1_file = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")
    renamer = _common.get_resource_path("bin/rcedit-x64.exe")

    posh = "C:\\Users\\Public\\posh.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\System.DirectoryServices.Protocols.test.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(exe_file, posh)
    _common.copy_file(user32, dll)
    _common.copy_file(ps1_file, ps1)
    _common.copy_file(renamer, rcedit)

    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command(
        [
            rcedit,
            dll,
            "--set-version-string",
            "OriginalFilename",
            "System.DirectoryServices.Protocols.test.dll",
        ]
    )

    log.info("Loading System.DirectoryServices.Protocols.test.dll")
    _ = _common.execute_command(
        [
            posh,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll};",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "88",
        ],
        timeout_secs=10,
    )

    _common.remove_files([posh, dll, ps1])
