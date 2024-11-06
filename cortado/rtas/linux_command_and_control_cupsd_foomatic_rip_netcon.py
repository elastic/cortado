# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8c634401-fd71-475e-b449-41b776b2b8c9",
    name="linux_command_and_control_cupsd_foomatic_rip_netcon",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="93d7b72d-3914-44fb-92bf-63675769ef12", name="Network Connection by Foomatic-rip Child"),
    ],
    techniques=["T1203"],
)
def main() -> None:
    # Path for the fake motd executable
    masquerade = "/tmp/foomatic-rip"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")

    log.info("Creating a fake motd executable..")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Execute the fake motd executable
    log.info("Executing the fake motd executable..")
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "53", "-c", "/tmp/foomatic-rip netcon -h 8.8.8.8 -p 53"]
    _ = _common.execute_command(commands, timeout_secs=5)

    # Cleanup
    _common.remove_file(masquerade)
