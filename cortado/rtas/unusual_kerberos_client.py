# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="78e59247-db65-412a-898c-2e757d695851",
    platforms=["windows"],
    endpoint_rules=[
        {"rule_name": "Execution from Suspicious Directory", "rule_id": "9ba39516-651e-489f-8b6a-f5501e0c492d"},
        {
            "rule_name": "Executable File Creation Followed by Immediate Network Connection",
            "rule_id": "8d11d741-7a06-41a1-a525-feaaa07ebbae",
        },
        {"rule_name": "Unusual Kerberos Client Process", "rule_id": "b5c91c3e-9d2d-4df6-afb7-c9d236b5ebe2"},
    ],
    siem_rules=[],
    techniques=["T1558", "T1204", "T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")


@_common.requires_os(*metadata.platforms)
def main():
    posh = "C:\\Users\\Public\\posh.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\System.DirectoryServices.Protocols.test.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, posh)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(RENAMER, rcedit)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute(
        [
            rcedit,
            dll,
            "--set-version-string",
            "OriginalFilename",
            "System.DirectoryServices.Protocols.test.dll",
        ]
    )

    _common.log("Loading System.DirectoryServices.Protocols.test.dll")
    _common.execute(
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
        timeout=10,
    )

    _common.remove_files(posh, dll, ps1)


if __name__ == "__main__":
    exit(main())
