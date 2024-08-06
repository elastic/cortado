# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="ac6b2cda-97f1-4095-b5f1-9791da2e6282",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[
        {
            'rule_id': 'e86da94d-e54b-4fb5-b96c-cecff87e8787',
            'rule_name': 'Installation of Security Support Provider'
        },
        {
            'rule_id': 'e9abe69b-1deb-4e19-ac4a-5d5ac00f72eb',
            'rule_name': 'Potential LSA Authentication Package Abuse'
        },
    ],
    techniques=['T1547', 'T1547.002', 'T1547.005'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    key = "SYSTEM\\ControlSet001\\Control\\Lsa\\Security Packages"
    key2 = "SYSTEM\\ControlSet001\\Control\\Lsa"
    value = "RTA"
    value2 = "Authentication Packages"
    data = "RTA"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
    with _common.temporary_reg(_common.HKLM, key2, value2, data):
        pass


if __name__ == "__main__":
    exit(main())
