# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="049f1e5e-99a9-4a0f-afac-b7b41b96ed12",
    platforms=["windows"],
    endpoint_rules=[
        {
            "rule_name": "Connection to WebService by an Unsigned Binary",
            "rule_id": "2c3efa34-fecd-4b3b-bdb6-30d547f2a1a4",
        }
    ],
    siem_rules=[],
    techniques=["T1102", "T1071"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    _common.log("Using PowerShell to connect to Google Drive")
    _common.execute([posh, "/c", "iwr", "https://drive.google.com", "-UseBasicParsing"], timeout=10)
    _common.remove_file(posh)


if __name__ == "__main__":
    exit(main())
