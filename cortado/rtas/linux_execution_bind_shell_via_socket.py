# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="793ae10f-c8a8-4385-8a95-1752f2281611",
    name="linux_execution_bind_shell_via_socket",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="37f6659f-dff4-42bc-91ae-7ed7a9264529", name="Bind Shell via Socket"),
    ],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/socket"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-s", "-p", "sh"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
