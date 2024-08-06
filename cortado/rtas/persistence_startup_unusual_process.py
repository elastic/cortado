# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata
import time


metadata = RtaMetadata(
    id="9a0c0715-5225-4170-a505-0e3cc4dfd63e",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
        {
            "rule_name": "Unusual File Written or Modified in Startup Folder",
            "rule_id": "30a90136-7831-41c3-a2aa-1a303c1186ac",
        },
        RuleMetadata(id="95d13ce1-ffb2-4be8-a56e-cc9a891e81e2", name="Startup Persistence via Unusual Process"),
        {
            "rule_name": "Script Interpreter Process Writing to Commonly Abused Persistence Locations",
            "rule_id": "be42f9fc-bdca-41cd-b125-f223d09eef69",
        },
        {
            "rule_name": "Startup Persistence via Windows Script Interpreter",
            "rule_id": "a85000c8-3eac-413b-8353-079343c2b6f0",
        },
    ],
    siem_rules=[],
    techniques=["T1547", "T1218", "T1036", "T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    tempowershell = "C:\\Windows\\notp0sh.exe"
    posh = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\posh.exe"
    _common.copy_file(powershell, tempowershell)

    time.sleep(2)
    _common.execute([tempowershell, "-c", "Copy-Item", powershell, tempowershell])
    _common.remove_files(tempowershell, posh)


if __name__ == "__main__":
    exit(main())
