# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="bf3591fe-ea36-49e0-af0e-21e927ecfc88",
    name="linux_execution_bind_shell_via_nc_traditional",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="0fb019ab-98a0-487e-aa37-fabe5b69ec8a", name="Bind Shell via Netcat Traditional"),
    ],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/nc"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-e", "-l", "-p", "/bin/sh"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
