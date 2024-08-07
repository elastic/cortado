# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="a6263f00-58b4-4555-b88f-9d66a7395891",
    name="reg_mod_shadow_rdp",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="c57f8579-e2a5-4804-847f-f2732edc5156", name="Potential Remote Desktop Shadowing Activity")
    ],
    techniques=["T1021"],
)
def main():
    _common.log("Modifying RDP Shadow reg key...")

    key = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services"
    value = "Shadow"
    data = "Test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
