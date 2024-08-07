# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="8896c6ac-ead6-4f4e-aecf-8308fd53e78c",
    name="reg_mod_port_forwarding",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="3535c8bb-3bd5-40f4-ae32-b7cd589d5372", name="Port Forwarding Rule Addition")],
    techniques=["T1572"],
)
def main():
    key = "System\\CurrentControlSet\\Services\\PortProxy\\v4tov4"
    value = "a"
    data = "0"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
