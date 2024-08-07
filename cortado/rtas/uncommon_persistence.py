# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="ca020d7f-f495-4f0a-a808-da615f3409b4",
    name="uncommon_persistence",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="97fc44d3-8dae-4019-ae83-298c3015600f", name="Startup or Run Key Registry Modification")
    ],
    techniques=["T1547"],
)
def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
    value = "Common Startup"
    data = "Test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
