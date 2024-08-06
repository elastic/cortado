# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="38cea037-c1a8-4749-a434-ba4c7d6e91f8",
    platforms=["windows"],
    endpoint_rules=[
        {
            "rule_name": "Privilege Escalation via Windir or SystemRoot Environment Variable",
            "rule_id": "18ffee0c-5f40-4dd8-aa9a-28251a308dbc",
        }
    ],
    siem_rules=[],
    techniques=["T1574"],
)


@_common.requires_os(*metadata.platforms)
def main():
    key = "System\\Environment"
    value = "windir"
    data = "rta"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
