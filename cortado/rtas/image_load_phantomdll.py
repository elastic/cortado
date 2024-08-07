# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="dabd91c9-101e-475d-b2f2-ca255abda003",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="bfeaf89b-a2a7-48a3-817f-e41829dc61ee",
            name="Suspicious DLL Loaded for Persistence or Privilege Escalation",
        )
    ],
    techniques=["T1574", "T1574.002", "T1574", "T1574.001"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    proc = "C:\\Users\\Public\\proc.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wlbsctrl.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, proc)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    # Execute command
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "wlbsctrl.dll"])

    _common.log("Loading wlbsctrl.dll into fake proc")
    _common.execute([proc, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    _common.remove_files(proc, dll, ps1)
