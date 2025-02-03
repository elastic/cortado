# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="96afe4b1-d8f3-4f95-b92b-645a39508174",
    name="linux_command_and_control_ip_address_arg_from_hidden_executable",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="c14705f7-ebd3-4cf7-88b3-6bff2d832f1b", name="Hidden Executable Initiated Egress Network Connection"
        ),
    ],
    techniques=["T1564"],
)
def main() -> None:
    log.info("Creating a fake hidden executable..")
    masquerade = "/tmp/.evil"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "netcon", "-h", "8.8.8.8", "-p", "53"]
    _ = _common.execute_command(commands, timeout_secs=5)

    log.info("Cleaning...")

    _common.remove_file(masquerade)

    log.info("Simulation successfull!")
