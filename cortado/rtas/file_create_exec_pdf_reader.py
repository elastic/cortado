# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="571e229f-fb92-48cf-b0fb-dd9630b1580f",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '1defdd62-cd8d-426e-a246-81a37751bb2b',
        'rule_name': 'Execution of File Written or Modified by PDF Reader'
    }],
    techniques=['T1566', 'T1566.001', 'T1566.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    rdrcef = "C:\\Users\\Public\\rdrcef.exe"
    arp = "C:\\Users\\Public\\arp.exe"
    temp = "C:\\Users\\Public\\temp.exe"
    _common.copy_file(EXE_FILE, rdrcef)
    _common.copy_file(EXE_FILE, arp)

    # Execute command
    _common.execute([rdrcef, "/c", "Copy-Item", arp, temp], timeout=5)
    _common.execute([temp], timeout=5, kill=True)
    _common.remove_files(rdrcef, arp, temp)


if __name__ == "__main__":
    exit(main())
