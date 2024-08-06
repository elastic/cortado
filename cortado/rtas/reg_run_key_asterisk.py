# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="13fbcfdc-ba84-414b-aaa6-49b416806c8e",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="94d35931-5c48-49ed-8c18-d601c4f8aeaa", name="Registry Run Key Prefixed with Asterisk")
    ],
    siem_rules=[],
    techniques=["T1547"],
)


@_common.requires_os(*metadata.platforms)
def main():
    _common.log("Writing registry key")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    value = "*test"
    data = "test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
