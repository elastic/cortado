# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="a6263f00-58b4-4555-b88f-9d66a7395891",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Suspicious NullSessionPipe Registry Modification",
            "rule_id": "11d374d8-2dad-4d9b-83a2-ee908eac8269",
        }
    ],
    siem_rules=[],
    techniques=["T1021", "T1112"],
)
def main():
    _common.log("Modifying NullSessionPipes reg key...")

    key = "SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters"
    value = "NullSessionPipes"
    data = "RpcServices"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


