# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import shutil
from pathlib import Path




@register_code_rta(
    id="7e9a94f4-46aa-45eb-b95b-53da7c01a033",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        {
            "rule_name": "UAC Bypass Attempt via CDSSync Scheduled Task Hijack",
            "rule_id": "d8b7a157-c98f-42bd-8aac-7d1e4fcd53f4",
        },
    ],
    siem_rules=[],
    techniques=["T1574", "T1548", "T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")



def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    taskhostw = "C:\\Users\\Public\\taskhostw.exe"
    path = "C:\\Users\\Public\\System32"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = path + "\\npmproxy.dll"
    Path(path).mkdir(parents=True, exist_ok=True)
    _common.copy_file(user32, dll)
    _common.copy_file(EXE_FILE, taskhostw)

    _common.log("Spawning PowerShell from fake taskhostw")
    _common.execute([taskhostw, "/c", powershell], timeout=10, kill=True)
    _common.remove_files(dll, taskhostw)
    shutil.rmtree(path)


