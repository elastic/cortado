# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="42eed432-af05-45d3-b788-7e3220f81f9a",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Suspicious ImageLoad via Windows Update Auto Update Client",
            "rule_id": "3788c03d-28a5-4466-b157-d6dd4dc449bb",
        }
    ],
    siem_rules=[],
    techniques=["T1218"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")



def main():
    wuauclt = "C:\\Users\\Public\\wuauclt.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, wuauclt)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    # Modify the originalfilename to invalidate the code sig
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.exe"])

    _common.log("Loading unsigned.dll into fake wuauclt")
    _common.execute(
        [
            wuauclt,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll}",
            ";echo",
            "/RunHandlerComServer",
            ";echo",
            "/UpdateDeploymentProvider",
        ],
        timeout=10,
    )

    _common.remove_files(wuauclt, dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
