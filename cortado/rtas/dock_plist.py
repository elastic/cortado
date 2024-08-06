# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="38c81994-958f-40c8-bb6a-20bc1b93d598",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        {"rule_name": "Persistence via Docker Shortcut Modification", "rule_id": "c81cefcb-82b9-4408-a533-3c3df549e62d"}
    ],
    techniques=["T1543"],
)


@_common.requires_os(*metadata.platforms)
def main():

    _common.log("Executing file modification on com.apple.dock.plist to mimic dock plist modification")
    _common.temporary_file_helper("testing", file_name=f"{Path.home()}/Library/Preferences/com.apple.dock.plist")


if __name__ == "__main__":
    exit(main())
