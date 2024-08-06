# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="bbbfc3e3-e1ba-45ad-9d30-cbbe115a0c6c",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="e13a65b7-f46f-4c7f-85cf-7e59170071fa", name="Execution via Internet Explorer Exporter"),
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
    ],
    siem_rules=[],
    techniques=["T1218"],
)

RENAMER = _common.get_path("bin", "rcedit-x64.exe")
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    dll = "C:\\Users\\Public\\sqlite3.dll"
    posh = "C:\\Users\\Public\\posh.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, dll)
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, posh, "--set-version-string", "OriginalFilename", "extexport.exe"])

    _common.log("Executing modified binary with extexport.exe original file name")
    _common.execute([posh], timeout=10, kill=True)

    _common.remove_files(dll, posh, rcedit)


if __name__ == "__main__":
    exit(main())
