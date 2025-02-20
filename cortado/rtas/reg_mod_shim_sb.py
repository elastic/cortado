# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="735969b3-6a2e-4c7d-b18a-59e2f36ef13b",
    name="reg_mod_shim_sb",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="c5ce48a6-7f57-4ee8-9313-3d0024caee10", name="Installation of Custom Shim Databases")],
    techniques=["T1546", "T1546.011"],
)
def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom"
    value = "a.sdb"
    data = "RTA"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
