# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="d87a9024-5e8e-44c2-b943-0680f92ad995",
    name="reg_mod_print_processors",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="8f3e91c7-d791-4704-80a1-42c160d7aa27",
            name="Potential Port Monitor or Print Processor Registration Abuse",
        )
    ],
    techniques=["T1547", "T1547.010", "T1547", "T1547.010"],
)
def main():
    key = "SYSTEM\\ControlSet001\\Control\\Print\\Monitors"
    value = "RTA"
    data = "RTA.dll"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
