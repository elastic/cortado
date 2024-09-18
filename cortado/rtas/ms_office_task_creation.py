# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="804463e7-b146-41ba-a757-d131d0a021ac",
    name="ms_office_task_creation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f9fd002c-0dab-42ec-8675-0cf5af6b4a85", name="Scheduled Task Creation via Microsoft Office"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c", name="Potential Masquerading as SVCHOST"),
    ],
    siem_rules=[],
    techniques=["T1036", "T1053", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    winword = "C:\\Users\\Public\\winword.exe"
    svchost = "C:\\Users\\Public\\svchost.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\taskschd.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    task = "C:\\Windows\\System32\\Tasks\\a.xml"
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, winword)
    _common.copy_file(EXE_FILE, svchost)

    log.info("Modifying the OriginalFileName")
    _ = _common.execute_command([rcedit, dll, "--set-version-string", "OriginalFilename", "taskschd.dll"])

    log.info("Loading taskschd.dll")
    _ = _common.execute_command([winword, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)
    _ = _common.execute_command([svchost, "-c", f"New-Item -Path {task} -Type File"], timeout_secs=10)
    _common.remove_files([dll, ps1, rcedit, task, winword, svchost])
