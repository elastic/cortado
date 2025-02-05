# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="50efd72e-147a-4f24-8c36-f8d1d69a9cfc",
    name="linux_execution_hidden_process_unusual_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="c52891b5-8f83-4571-8e68-ea2601f46285", name="Suspicious Execution via a Hidden Process"),
    ],
    techniques=["T1059", "T1564", "T1071"],
)
def main() -> None:
    log.info("Creating a fake hidden executable..")
    masquerade = "/tmp/.evil"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "/dev/tcp"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
