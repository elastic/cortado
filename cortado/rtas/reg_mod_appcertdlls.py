# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="4c0e7d24-63d1-4888-9ea4-0d920ce3fe40",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '513f0ffd-b317-4b9c-9494-92ce861f22c7', 'rule_name': 'Registry Persistence via AppCert DLL'}],
    techniques=['T1546', 'T1546.009'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    key = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs"
    value = "RTA"
    data = "NotMalicious"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
