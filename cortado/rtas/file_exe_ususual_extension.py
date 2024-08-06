# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="5370760b-09ea-4258-bcfa-e426726a4777",
    platforms=["windows"],
    endpoint_rules=[
        {"rule_name": "Execution via Renamed Signed Binary Proxy", "rule_id": "b0207677-5041-470b-981d-13ab956cf5b4"},
        {"rule_name": "Executable with Unusual Filename", "rule_id": "d1b6319f-2933-4872-8e67-5728fd09a4a1"},
        {
            "rule_name": "Process Execution with Unusual File Extension",
            "rule_id": "6daf97b0-8e29-476b-998a-c3d168d98506",
        },
    ],
    siem_rules=[],
    techniques=["T1218", "T1036"],
)


@_common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    unusualext = "C:\\Users\\Public\\powershell.exe.pdf"
    _common.copy_file(powershell, unusualext)

    _common.execute([unusualext], timeout=1, kill=True)
    _common.remove_file(unusualext)


if __name__ == "__main__":
    exit(main())
