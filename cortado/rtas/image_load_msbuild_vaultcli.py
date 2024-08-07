# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="d4b4f924-974b-4033-9728-bb6a736bf7ef",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae5',
        'rule_name': 'Potential Credential Access via Trusted Developer Utility'
    }],
    techniques=['T1003'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")



def main():
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\vaultcli.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(user32, dll)
    _common.copy_file(EXE_FILE, msbuild)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "vaultcli.dll"])

    _common.log("Loading System.DirectoryServices.Protocols.test.dll")
    _common.execute([msbuild, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    _common.remove_files(dll, ps1, rcedit, msbuild)


if __name__ == "__main__":
    exit(main())
