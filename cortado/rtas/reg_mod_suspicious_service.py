# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="ffc9ace1-3527-46e3-bc3e-86b942107edb",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '36a8e048-d888-4f61-a8b9-0f9e2e40f317', 'rule_name': 'Suspicious ImagePath Service Creation'}],
    techniques=['T1543', 'T1543.003'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    key = "SYSTEM\\ControlSet001\\Services\\RTA"
    value = "ImagePath"
    data = "%COMSPEC%"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
