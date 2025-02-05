# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1b24ddc7-c01c-4d24-a00e-0738a40b6dd6",
    name="linux_sus_netcon_command_exec",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="8c2977dd-07ce-4a8e-8ccd-5e4183138675", name="Network Connection Followed by Command Execution"
        ),
    ],
    techniques=["T1071", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/dev/shm/netcon"
    masquerade2 = "/dev/shm/bash"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    source2 = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    _common.copy_file(source2, masquerade2)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])
    _ = _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade2, masquerade, "chain", "-h", "8.8.8.8", "-p", "53", "-c", "whoami"]
    _ = _common.execute_command(commands, timeout_secs=5, shell=True)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    log.info("Simulation successfull!")
