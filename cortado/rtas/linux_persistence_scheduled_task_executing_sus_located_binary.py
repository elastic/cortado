# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="5b9be46b-18f2-4b74-9003-36d763c5d887",
name="linux_persistence_scheduled_task_executing_sus_located_binary",    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="f2a52d42-2410-468b-9910-26823c6ef822", name="Scheduled Job Executing Binary in Unusual Location"),
    ],
    techniques=["T1543", "T1053", "T1543"],
)
def main() -> None:
    log.info("Creating a fake cron executable..")
    masquerade = "/tmp/cron"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "/dev/shm/foo"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
