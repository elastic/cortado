# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="e70ab2f3-7a67-4cd8-9969-ad4ebe0358bc",
    name="reg_mod_disableantispyware",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="fe794edd-487f-4a90-b285-3ee54f2af2d3", name="Microsoft Windows Defender Tampering"),
        RuleMetadata(
            id="2ffa1f1e-b6db-47fa-994b-1512743847eb", name="Windows Defender Disabled via Registry Modification"
        ),
    ],
    techniques=["T1562", "T1562.001", "T1562.006"],
)
def main():
    key = "SOFTWARE\\Policies\\Microsoft\\Windows Defender"
    value = "DisableAntiSpyware"
    data = 1

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data, data_type="dword"):
        pass
