# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="5781ea36-ac63-4746-8e0f-a1ebd5ec481d",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '203ab79b-239b-4aa5-8e54-fc50623ee8e4',
        'rule_name': 'Creation or Modification of Root Certificate'
    }],
    techniques=['T1553', 'T1553.004'],
)


@_common.requires_os(*metadata.platforms)
def main():
    key = "Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\Test"
    value = "Blob"
    data = "test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
