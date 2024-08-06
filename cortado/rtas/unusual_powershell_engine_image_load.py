# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="a5d82c62-6d4e-4d31-94f2-a996c9613604",
    platforms=["windows"],
    endpoint_rules=[{"rule_name": "Unusual PowerShell Engine ImageLoad", "rule_id": "f57505bb-a1d2-4d3b-b7b5-1d81d7bdb80e"}],
    siem_rules=[],
    techniques=["T1059"],
)


@_common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    posh = "C:\\Windows\\System32\\posh.exe"
    _common.copy_file(powershell, posh)

    _common.log("Executing renamed powershell on system32 folder")
    _common.execute([posh, "-c", "echo RTA"], timeout=10)
    _common.remove_files(posh)


if __name__ == "__main__":
    exit(main())
