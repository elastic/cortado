# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="bcdda7c2-cc0c-4555-8dda-86a3263c99ad",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '1a6075b0-7479-450e-8fe7-b8b8438ac570',
        'rule_name': 'Execution of COM object via Xwizard'
    }],
    techniques=['T1559', 'T1559.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")


@_common.requires_os(*metadata.platforms)
def main():
    xwizard = "C:\\Users\\Public\\xwizard.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, xwizard)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, xwizard, "--set-version-string", "OriginalFilename", "xwizard.exe"])

    _common.execute([xwizard], timeout=2, kill=True)

    _common.remove_files(rcedit, xwizard)


if __name__ == "__main__":
    exit(main())
