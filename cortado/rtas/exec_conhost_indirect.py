# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="32e926c2-2f33-4dd0-ac77-12545331d3e4",
    platforms=["windows"],
    endpoint_rules=[
        {
            'rule_id': '4b61b37d-c569-444a-bafa-e29d221ee55c',
            'rule_name': 'Indirect Command Execution via Console Window Host'
        }
    ],
    siem_rules=[],
    techniques=['T1202'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    conhost = "C:\\Users\\Public\\conhost.exe"
    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, conhost)
    _common.copy_file(EXE_FILE, posh)

    _common.execute([conhost, posh], timeout=10, kill=True)
    _common.remove_files(conhost, posh)


if __name__ == "__main__":
    exit(main())
