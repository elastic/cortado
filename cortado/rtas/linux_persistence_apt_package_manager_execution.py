# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="305b2daa-2ef4-4cdd-8ed2-d751174cbdcc",
    name="linux_persistence_apt_package_manager_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="cd0844ea-6112-453f-a836-cc021a2b6afb", name="APT Package Manager Command Execution"),
    ],
    techniques=["T1543", "T1059", "T1546"],
)
def main() -> None:
    log.info("Creating a fake apt executable..")
    masquerade = "/tmp/apt"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    log.info("Creating a fake openssl executable..")
    masquerade2 = "/tmp/openssl"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade2)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade, "exec", "-c", "/tmp/openssl"]
    _ = _common.execute_command(commands, timeout_secs=5)

    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)

    log.info("Simulation successfull!")
