# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f94f70a3-7c63-4f75-b5bc-f2227e284934",
    name="exec_echo_named_pipe",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="a0265178-779d-4bc5-b3f1-abb3bcddedab", name="Privilege Escalation via Named Pipe Impersonation"
        )
    ],
    techniques=["T1134"],
)
def main():
    # Execute command
    _ = _common.execute_command(["cmd.exe", "/c", "'echo", "cmd.exe", ">", "\\\\.\\pipe\\named'"], timeout_secs=5)
