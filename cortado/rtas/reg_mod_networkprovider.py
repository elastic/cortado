# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1b4050d9-e3fa-4559-b188-522b620584c8",
    name="reg_mod_networkprovider",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="54c3d186-0461-4dc3-9b33-2dc5c7473936", name="Network Logon Provider Registry Modification")
    ],
    techniques=["T1556", "T1543"],
)
def main():
    key = "System\\CurrentControlSet\\Services\\Test\\NetworkProvider"
    value = "ProviderPath"
    data = "C:\\Nonexistent.exe"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
