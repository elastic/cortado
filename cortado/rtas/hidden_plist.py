# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

from pathlib import Path

metadata = RtaMetadata(
    id="6df524fe-6a1a-417f-8f70-d6140ef739e2",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '092b068f-84ac-485d-8a55-7dd9e006715f',
        'rule_name': 'Creation of Hidden Launch Agent or Daemon'
    }],
    techniques=[""],
)


@_common.requires_os(*metadata.platforms)
def main():

    _common.log(f"Executing hidden plist creation on {Path.home()}/Library/LaunchAgents/.test.plist")
    _common.temporary_file_helper("testing", file_name=f"{Path.home()}/Library/LaunchAgents/.test.plist")


if __name__ == "__main__":
    exit(main())
