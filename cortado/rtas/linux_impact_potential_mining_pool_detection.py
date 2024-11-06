# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5abebdea-b42e-4401-8838-15f19d11401f",
    name="linux_impact_potential_mining_pool_detection",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="fcc42a61-4507-4918-867b-d673e5b065dc", name="Potential Mining Pool Command Detection"),
    ],
    techniques=["T1496", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/dev/shm/evil"

    source = _common.get_resource_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "crypto-pool.info"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
