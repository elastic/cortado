# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="88b8c5e8-43d4-4063-9d0f-e1fc3063447b",
    name="linux_defense_evasion_hex_payload_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="f2d206e0-97c9-484b-8b6a-5eecd82fbfdc", name="Hexadecimal Payload Execution"),
    ],
    techniques=["T1027", "T1140", "T1059", "T1204"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/evil"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
