# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="ac1f9204-f612-4d50-9de0-6dabcd589816",
    name="linux_persistence_initd_netcon",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="b38eb534-230c-45f4-93ba-fc516ac51630", name="System V Init (init.d) Egress Network Connection"
        ),
    ],
    techniques=["T1037", "T1071"],
)
def main() -> None:
    # Path for the fake initd executable
    masquerade = "/etc/init.d/rta"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")

    log.info("Creating a fake initd executable..")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Execute the fake initd executable
    log.info("Executing the fake initd executable..")
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "53", "-c", "/etc/init.d/rta netcon -h 8.8.8.8 -p 53"]
    _ = _common.execute_command(commands, timeout_secs=5)

    # Cleanup
    _common.remove_file(masquerade)
