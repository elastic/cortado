# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ffc9ace1-3527-46e3-bc3e-86b942107edb",
    name="reg_mod_suspicious_service",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="36a8e048-d888-4f61-a8b9-0f9e2e40f317", name="Suspicious ImagePath Service Creation")],
    techniques=["T1543", "T1543.003"],
)
def main():
    key = "SYSTEM\\ControlSet001\\Services\\RTA"
    value = "ImagePath"
    data = "%COMSPEC%"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
