# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2edd7889-578b-4870-befd-6b3d0f5a10fd",
    name="reg_mod_builtindnsclientenabled",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="a22a09c2-2162-4df0-a356-9aacbeb56a04", name="DNS-over-HTTPS Enabled via Registry")],
    techniques=["T1562"],
)
def main():
    key = "SOFTWARE\\Policies\\Microsoft\\Edge"
    value = "BuiltInDnsClientEnabled"
    data = 1

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data, data_type="dword"):
        pass
