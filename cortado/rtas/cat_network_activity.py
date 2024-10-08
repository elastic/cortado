# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="fcd2d0fe-fed2-424a-bdc5-e9bef5031344",
    name="cat_network_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="25ae94f5-0214-4bf1-b534-33d4ffc3d41c", name="Network Activity Detected via cat")],
    siem_rules=[RuleMetadata(id="afd04601-12fc-4149-9b78-9c3f8fe45d39", name="Network Activity Detected via cat")],
)
def main():
    log.info("Creating a fake cat executable..")
    masquerade = "/tmp/cat"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)

    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "netcon", "-h", "127.0.0.1", "-p", "1337"]

    log.info("Simulating cat network activity..")
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cat network simulation successful!")
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("RTA completed!")
