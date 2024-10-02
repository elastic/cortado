# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="cd2154fa-de1a-4098-83c1-be1ab23da379",
    name="reg_mod_driver_blocklist",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="31b7218e-ba98-4228-a39a-d0e0d1c0e5b7", name="Attempt to Disable Windows Driver Blocklist via Registry"
        )
    ],
    techniques=["T1112"],
)
def main():
    key = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
    value = "VulnerableDriverBlocklistEnable"
    data = 0

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data, data_type="dword"):
        pass
