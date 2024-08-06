# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="ada7805f-e0e1-4633-952e-41f5bb392fdb",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '93c1ce76-494c-4f01-8167-35edfb52f7b1',
        'rule_name': 'Encoded Executable Stored in the Registry'
    }],
    techniques=['T1112', 'T1140'],
)


@_common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Policies\\Test"
    value = "Base64"
    data = "TVqQAAMAAAAEAAAA"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
