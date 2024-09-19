# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="0e5a4099-f76d-43f8-aa91-0ed1ad5fed81",
    name="reg_mod_remcos",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="9769d372-4115-4ef8-8d7b-aaad05dad9ae", name="Remcos RAT Registry or File Modification")
    ],
    siem_rules=[],
    techniques=["T1112"],
)
def main():
    log.info("Temporarily creating a Remcos RAT alike reg key...")

    key = "SOFTWARE\\Remcos-rta"
    value = "licence"
    data = "RAT"

    with _common.temp_registry_value(_const.REG_HKCU, key, value, data):
        pass
