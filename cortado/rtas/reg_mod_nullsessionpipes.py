# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="a6263f00-58b4-4555-b88f-9d66a7395891",
    name="reg_mod_nullsessionpipes",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="11d374d8-2dad-4d9b-83a2-ee908eac8269", name="Suspicious NullSessionPipe Registry Modification")
    ],
    siem_rules=[],
    techniques=["T1021", "T1112"],
)
def main():
    log.info("Modifying NullSessionPipes reg key...")

    key = "SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters"
    value = "NullSessionPipes"
    data = "RpcServices"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
