# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="712509fa-5326-4ebc-bb1e-82ddf28e8baa",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '9aa0e1f6-52ce-42e1-abb3-09657cee2698', 'rule_name': 'Scheduled Tasks AT Command Enabled'}],
    techniques=['T1562', 'T1562.001'],
)


@_common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Configuration"
    value = "EnableAt"
    data = 1

    with _common.temporary_reg(_common.HKLM, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
