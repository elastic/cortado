# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="1f0afcd1-e091-4489-a750-5b0b44e69e45",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '053a0387-f3b5-4ba5-8245-8002cca2bd08',
        'rule_name': 'Potential DLL Side-Loading via Microsoft Antimalware Service Executable'
    }],
    techniques=['T1574', 'T1574.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")


@_common.requires_os(*metadata.platforms)
def main():
    msmpeng = "C:\\Users\\Public\\MsMpEng.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, msmpeng)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, msmpeng, "--set-version-string", "OriginalFilename", "MsMpEng.exe"])

    _common.execute([msmpeng], timeout=2, kill=True)

    _common.remove_files(rcedit, msmpeng)


if __name__ == "__main__":
    exit(main())
