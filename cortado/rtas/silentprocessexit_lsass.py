# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="bf2f893a-513a-41ea-9170-2c9b08a2a55f",
    platforms=["windows"],
    endpoint_rules=[{"rule_name": "LSA Dump via SilentProcessExit", "rule_id": "28969fe6-0ebe-4442-b40c-dbe9b4234f5e"}],
    siem_rules=[],
    techniques=["T1003"],
)


@_common.requires_os(*metadata.platforms)
def main():
    _common.log("Temporarily creating LSA SilentProcessExit reg key...")

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"
    value = "lsass.exe"
    data = "0"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
