# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="374718be-d841-4381-a75f-ef54f0d5eb18",
    platforms=["windows"],
    endpoint_rules=[
        {"rule_name": "Credential Access via Known Utilities", "rule_id": "3c44fc50-2672-48b3-af77-ff43b895ac70"}
    ],
    siem_rules=[],
    techniques=["T1003"],
)

EXE_FILE = _common.get_path("bin", "renamed.exe")


@_common.requires_os(*metadata.platforms)
def main():
    binary = "ProcessDump.exe"
    _common.copy_file(EXE_FILE, binary)

    # Execute command
    _common.execute([binary], timeout=5, kill=True)

    _common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
