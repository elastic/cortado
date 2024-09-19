# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="31fdd029-5fac-474f-9201-3b7bfb60e0cf",
    name="reg_mod_plugx",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7a201712-9f3c-4f40-b4fc-2418a44b8ecb", name="Potential PlugX Registry Modification")
    ],
    siem_rules=[],
    techniques=["T1547", "T1112", "T1219"],
)
def main():
    log.info("Temporarily creating a PlugX-like reg key...")

    key = "SOFTWARE\\CLASSES\\ms-pu\\PROXY"
    value = "Test"
    data = "Test"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
