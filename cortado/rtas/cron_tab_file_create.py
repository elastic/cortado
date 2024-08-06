# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="e85f7e39-da36-4ed4-be00-c5b29f4d763c",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "Cron Tab Creation or Modification by an Unusual Process",
            "rule_id": "e5fc1285-d312-4b45-9e6b-e6c037276c17",
        }
    ],
    siem_rules=[],
    techniques=["T1053", "T1053.003"],
)


@_common.requires_os(*metadata.platforms)
def main():

    _common.log("Executing file creation on /private/var/at/tabs/test.")
    _common.temporary_file_helper("testing", file_name="/private/var/at/tabs/test")


if __name__ == "__main__":
    exit(main())
