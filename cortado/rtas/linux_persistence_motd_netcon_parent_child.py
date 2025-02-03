# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="a67ba2b1-cace-4cb9-9b7e-12c9ffe136cb",
name="linux_persistence_motd_netcon_parent_child",    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="da02d81a-d432-4cfe-8aa4-fc1a31c29c98", name="Egress Network Connection by MOTD Child"),
    ],
    techniques=["T1037", "T1059", "T1071"],
)
def main() -> None:
    # Path for the fake motd executable
    masquerade = "/etc/update-motd.d/rta"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")

    log.info("Creating a fake motd executable..")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Execute the fake motd executable
    log.info("Executing the fake motd executable..")
    commands = [
        masquerade,
        "chain",
        "-h",
        "8.8.8.8",
        "-p",
        "53",
        "-c",
        "/etc/update-motd.d/rta netcon -h 8.8.8.8 -p 53",
    ]
    _ = _common.execute_command(commands, timeout_secs=5)

    # Cleanup
    _common.remove_file(masquerade)
