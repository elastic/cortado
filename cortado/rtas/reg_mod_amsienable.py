# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="78715019-6eff-45b1-a942-47db87d55b01",
    name="reg_mod_amsienable",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="f874315d-5188-4b4a-8521-d1c73093a7e4", name="Modification of AmsiEnable Registry Key")
    ],
    techniques=["T1562", "T1562.001"],
)
def main():
    key = "Software\\Microsoft\\Windows Script\\Settings"
    value = "AmsiEnable"
    data = 0

    with _common.temp_registry_value(_const.REG_HKCU, key, value, data, data_type="dword"):
        pass
