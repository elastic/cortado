# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="fd5fb7a8-398a-4322-ae28-8f88cce6aa88",
    name="linux_execution_interactive_shell_spawn_from_hidden_process",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="52deef30-e633-49e1-9dd2-da1ad6cb5e43", name="Interactive Shell Spawned via Hidden Process"),
    ],
    techniques=["T1059", "T1564"],
)
def main() -> None:
    log.info("Creating a fake hidden executable..")
    masquerade = "/tmp/.evil"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "-i"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
