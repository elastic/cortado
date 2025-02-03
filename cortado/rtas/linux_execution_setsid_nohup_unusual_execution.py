# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="66ff975c-fa48-47c4-965a-8f363425369e",
    name="linux_execution_setsid_nohup_unusual_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="18d82674-08d0-408e-801b-468e1b06298f", name="Suspicious Execution via setsid and nohup"),
    ],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake nohup executable..")
    masquerade = "/tmp/nohup"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "/dev/tcp"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
