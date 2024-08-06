# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
from pathlib import Path

from . import RtaMetadata, _common


metadata = RtaMetadata(
    id="1d486055-38f8-4cf3-aec1-7f4f72d73fb2",
    platforms=["windows"],
    endpoint_rules=[
        {
            "rule_name": "UAC Bypass via Unsafe Deserialization in Event Viewer",
            "rule_id": "df7e55c9-cd36-4e33-9e82-3a54b9c84495",
        }
    ],
    siem_rules=[],
    techniques=["T1548"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    appdata = os.getenv("LOCALAPPDATA")
    path = Path(appdata) / "\\Microsoft\\Event Viewer"
    recentfiles = path / "\\RecentViews"

    if path.is_dir():
        _common.copy_file(EXE_FILE, recentfiles)
        _common.remove_file(recentfiles)
    else:
        path.mkdir()
        _common.copy_file(EXE_FILE, recentfiles)
        _common.remove_file(recentfiles)
        path.rmdir()


if __name__ == "__main__":
    exit(main())
