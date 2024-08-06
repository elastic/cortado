# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="31fdd029-5fac-474f-9201-3b7bfb60e0cf",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="7a201712-9f3c-4f40-b4fc-2418a44b8ecb", name="Potential PlugX Registry Modification")
    ],
    siem_rules=[],
    techniques=["T1547", "T1112", "T1219"],
)


@_common.requires_os(*metadata.platforms)
def main():
    _common.log("Temporarily creating a PlugX-like reg key...")

    key = "SOFTWARE\\CLASSES\\ms-pu\\PROXY"
    value = "Test"
    data = "Test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
