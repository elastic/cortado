# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="cd2154fa-de1a-4098-83c1-be1ab23da379",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="31b7218e-ba98-4228-a39a-d0e0d1c0e5b7", name="Attempt to Disable Windows Driver Blocklist via Registry"
        )
    ],
    siem_rules=[],
    techniques=["T1112"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    key = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
    value = "VulnerableDriverBlocklistEnable"
    data = 0

    with _common.temporary_reg(_common.HKLM, key, value, data, data_type="dword"):
        pass
