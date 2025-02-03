# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="2e476fe9-9c70-4276-a224-2f22ba149eea",
    name="linux_execution_reverse_shell_or_listener_via_socat",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="613da93c-226e-4150-9125-3b476103c0b9", name="Socat Reverse Shell or Listener Activity"),
    ],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/socat"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "exec tcp"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
