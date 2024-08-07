# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="9cca3284-848f-483a-9241-48562eee0605",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': '4b4ba027-151f-40e4-99ba-a386735c27e4',
        'rule_name': 'Unsigned DLL Loaded by Windows Tasks Host'
    }],
    siem_rules=[],
    techniques=['T1053', 'T1053.005'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")



def main():
    taskhost1 = "C:\\Users\\Public\\taskhost1.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(user32, dll)
    _common.copy_file(EXE_FILE, taskhost1)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.dll"])

    _common.log("Loading unsigned DLL into fake taskhost")
    _common.execute([taskhost1, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    _common.remove_files(dll, ps1, rcedit)


