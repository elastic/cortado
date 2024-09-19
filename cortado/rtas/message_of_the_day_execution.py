# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="33f3ebda-7776-4cec-933b-48e85d707d61",
    name="message_of_the_day_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="b9b3922a-59ee-407c-8773-31b98bf9b18d", name="Suspicious Process Spawned from MOTD Detected")
    ],
    siem_rules=[
        RuleMetadata(id="4ec47004-b34a-42e6-8003-376a123ea447", name="Suspicious Process Spawned from MOTD Detected")
    ],
    techniques=[""],
)
def main():
    log.info("Creating a fake MOTD executable..")
    masquerade = "/etc/update-motd.d/evil"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)

    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "netcat"]

    log.info("Simulating MOTD netcat activity..")
    _ = _common.execute_command([*commands], timeout_secs=5)
    log.info("MOTD netcat simulation successful!")
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("RTA completed!")
