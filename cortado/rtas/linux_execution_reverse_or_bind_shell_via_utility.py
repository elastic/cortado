# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8f5607f7-4c55-4458-b908-b2cb22c54cf4",
    name="linux_execution_reverse_or_bind_shell_via_utility",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="bb330560-0042-48a5-8232-7f2012d6e440", name="Reverse or Bind Shell via Suspicious Utility"),
    ],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/vim"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-c", "socket"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
