# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1ab728b4-1c06-4be4-a834-7893f1e9a26e",
    name="linux_execution_bind_shell_via_node",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="08697d36-4c07-4f54-b177-a39e473705c0", name="Bind Shell via Node"),
    ],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/node"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-e", "spawnsh", "listen"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
