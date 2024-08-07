# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="f94f70a3-7c63-4f75-b5bc-f2227e284934",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Privilege Escalation via Named Pipe Impersonation",
            "rule_id": "a0265178-779d-4bc5-b3f1-abb3bcddedab",
        }
    ],
    siem_rules=[],
    techniques=["T1134"],
)
def main():
    # Execute command
    _common.execute(["cmd.exe", "/c", "'echo", "cmd.exe", ">", "\\\\.\\pipe\\named'"], timeout=5)


