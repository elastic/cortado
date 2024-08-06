# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import platform
from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="62eb4521-cfb8-4fb8-bc6d-792fe57273b7",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "Potential Binary Masquerading via Invalid Code Signature",
            "rule_id": "4154c8ce-c718-4641-80db-a6a52276f1a4",
        }
    ],
    siem_rules=[],
    techniques=["T1036"],
)


@_common.requires_os(*metadata.platforms)
def main():

    if platform.processor() == "arm":
        name = "com.apple.sleep_arm"
    else:
        name = "com.apple.sleep_intel"
    path = _common.get_path("bin", name)
    _common.execute([path, "5"], kill=True)


if __name__ == "__main__":
    exit(main())
