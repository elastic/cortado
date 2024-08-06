# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="e7f3a729-e5ee-462b-ba1c-dd778468d24d",
    platforms=["windows"],
    endpoint_rules=[
        {
            'rule_id': 'aafe3c78-15d9-4853-a602-663b8fada5b5',
            'rule_name': 'Potential Evasion via Intel GfxDownloadWrapper'
        }
    ],
    siem_rules=[],
    techniques=['T1218', 'T1105'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    gfx = "C:\\Users\\Public\\GfxDownloadWrapper.exe"
    _common.copy_file(EXE_FILE, gfx)

    _common.execute([gfx, "/c", "echo", "run", "0", "http"], timeout=5, kill=True)
    _common.remove_files(gfx)


if __name__ == "__main__":
    exit(main())
