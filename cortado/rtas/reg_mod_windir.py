# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="38cea037-c1a8-4749-a434-ba4c7d6e91f8",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="18ffee0c-5f40-4dd8-aa9a-28251a308dbc",
            name="Privilege Escalation via Windir or SystemRoot Environment Variable",
        )
    ],
    siem_rules=[],
    techniques=["T1574"],
)
def main():
    key = "System\\Environment"
    value = "windir"
    data = "rta"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass
