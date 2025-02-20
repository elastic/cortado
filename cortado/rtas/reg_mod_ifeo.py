# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2bb1016f-b3e9-455d-b665-02a0aafc797a",
    name="reg_mod_ifeo",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="ff5fd85a-e770-4e57-8bae-0d267442eb9f", name="Suspicious Image File Execution Options Modification"
        )
    ],
    techniques=["T1546", "T1546.012"],
)
def main():
    log.info("Temp Registry mod: IFEO")

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rta.exe\\"
    value = "Debugger"
    data = "Test"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
