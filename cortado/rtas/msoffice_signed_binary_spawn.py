# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="498c13e2-789c-4a6c-b32d-0589d2f907c2",
    platforms=["windows"],
    endpoint_rules=[
        {
            "rule_name": "Signed Binary Execution via Microsoft Office",
            "rule_id": "321e7877-075a-4582-8eff-777dde15e787",
        },
        {"rule_name": "Execution via Renamed Signed Binary Proxy", "rule_id": "b0207677-5041-470b-981d-13ab956cf5b4"},
    ],
    siem_rules=[],
    techniques=["T1574", "T1218", "T1566"],
)


@_common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    temposh = "C:\\Users\\Public\\posh.exe"
    binary = "C:\\Users\\Public\\winword.exe"
    _common.copy_file(powershell, binary)

    # Execute command
    _common.log("Dropping executable using fake winword")
    _common.execute([binary, "/c", f"Copy-Item {powershell} {temposh}"], timeout=10)

    _common.log("Executing it using fake winword")
    _common.execute([binary, "/c", temposh], kill=True)

    _common.remove_files(binary, temposh)


if __name__ == "__main__":
    exit(main())
