# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="5ef57ec6-32a0-40b2-b9a7-c4eda4cd3e49",
    name="reg_mod_enablescriptblocklogging",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="818e23e6-2094-4f0e-8c01-22d30f3506c6", name="PowerShell Script Block Logging Disabled")
    ],
    techniques=["T1562", "T1562.002"],
)
def main():
    key = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
    value = "EnableScriptBlockLogging"
    data = 0

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data, data_type="dword"):
        pass
