# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="32462f3e-d5af-4ef9-8260-aa9fbeb6e117",
    name="reg_mod_autodialdll",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="2ffc3943-8100-4f77-9c8f-e8f9e185604b", name="Persistence via AutodialDLL Registry Modification"
        )
    ],
    techniques=["T1112"],
)
def main():
    key = "SYSTEM\\ControlSet001\\Services\\WinSock2\\Parameters"
    value = "AutodialDLL"
    data = "RTA"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
