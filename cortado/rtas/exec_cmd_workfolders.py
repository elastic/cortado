# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="a555c960-08af-49fe-8889-18434a604f68",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': 'ad0d2742-9a49-11ec-8d6b-acde48001122',
        'rule_name': 'Signed Proxy Execution via MS Work Folders'
    }],
    techniques=['T1218'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    workfolders = "C:\\Users\\Public\\WorkFolders.exe"
    control = "C:\\Users\\Public\\control.exe"
    _common.copy_file(EXE_FILE, workfolders)
    _common.copy_file(EXE_FILE, control)

    # Execute command
    _common.execute([workfolders, "/c", control], timeout=2, kill=True)
    _common.remove_files(workfolders, control)


if __name__ == "__main__":
    exit(main())
