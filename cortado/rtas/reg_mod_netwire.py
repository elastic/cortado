# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="2bb1f4df-dc38-45a6-a0f4-54660c93a652",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="102f340f-1839-4bad-8493-824cc02c4e69", name="NetWire RAT Registry Modification")],
    siem_rules=[],
    techniques=["T1112"],
)
def main():
    _common.log("Temporarily creating a Netwire RAT-like reg key...")

    key = "SOFTWARE\\Netwire"
    value = "HostId"
    data = "Test"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass


