# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="084c5d8f-2578-4fe0-bc6f-f6c44205804a",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "At Job Creation or Modification by an Unusual Process",
            "rule_id": "779f18ce-1457-457c-80e1-3a5d146c2dc0",
        }
    ],
    siem_rules=[],
    techniques=["T1053", "T1053.002"],
)


@_common.requires_os(*metadata.platforms)
def main():

    _common.log("Executing file creation on /private/var/at/jobs/test.")
    _common.temporary_file_helper("testing", file_name="/private/var/at/jobs/test")


if __name__ == "__main__":
    exit(main())
