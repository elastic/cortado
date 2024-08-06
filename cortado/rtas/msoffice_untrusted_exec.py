# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="9d5af763-b3f9-4b89-96b6-16e0210f9755",
    platforms=["windows"],
    endpoint_rules=[
        {
            "rule_name": "Network Connection via Process with Unusual Arguments",
            "rule_id": "95601d8b-b969-4189-9744-090140ae29e6",
        },
        {
            "rule_name": "Untrusted File Execution via Microsoft Office",
            "rule_id": "bb23a662-2d75-4714-837d-4ec9c2e772a5",
        },
        RuleMetadata(id="901f0c30-a7c5-40a5-80e3-a50c6744632f", name="RunDLL32/Regsvr32 Loads Dropped Executable"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1055", "T1566", "T1059"],
)

EXE_FILE = _common.get_path("bin", "regsvr32.exe")
EXE_FILE2 = _common.get_path("bin", "renamed.exe")


@_common.requires_os(*metadata.platforms)
def main():
    binary = "winword.exe"
    _common.copy_file(EXE_FILE2, binary)

    # Execute command
    fake_regsvr = "C:\\Users\\Public\\regsvr32.exe"
    _common.log("Dropping executable using fake winword")
    _common.execute([binary, "/c", f"copy {EXE_FILE} {fake_regsvr}"])

    _common.log("Executing it to create an untrusted child process")
    _common.execute([binary, "/c", fake_regsvr])

    _common.remove_files(binary, fake_regsvr)


if __name__ == "__main__":
    exit(main())
