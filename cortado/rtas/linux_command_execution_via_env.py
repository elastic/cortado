# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0a3d2e78-1860-48e9-b4c8-99dcc7dc0e87",
    name="linux_command_execution_via_env",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="a393fff6-3735-440e-8536-82509d78bfdd", name="Linux Command Execution via Env Binary")
    ],
    techniques=["T1059", "T1033", "T1105"],
)
def main():
    # List of commands to be executed by 'env'
    command = "/bin/bash -c whoami"
    env_command = f"/usr/bin/env {command}"

    # Execute the 'env' command which in turn executes the child command
    log.info(f"Executing 'env' with child command: {command}")
    _ = _common.execute_command(env_command, shell=True)

    log.info("RTA execution completed.")
