# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="8b03eda5-5c01-4e69-9095-f9c00af85000",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="14ed1aa9-ebfd-4cf9-a463-0ac59ec55204", name="Potential Persistence via Time Provider Modification"
        )
    ],
    techniques=["T1547", "T1547.003"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    key = "SYSTEM\\ControlSet001\\Services\\W32Time\\TimeProviders"
    value = "Test"
    data = "a.dll"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
