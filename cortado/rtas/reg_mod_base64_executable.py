# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="ada7805f-e0e1-4633-952e-41f5bb392fdb",
    name="reg_mod_base64_executable",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="93c1ce76-494c-4f01-8167-35edfb52f7b1", name="Encoded Executable Stored in the Registry")
    ],
    techniques=["T1112", "T1140"],
)
def main():
    key = "SOFTWARE\\Policies\\Test"
    value = "Base64"
    data = "TVqQAAMAAAAEAAAA"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
