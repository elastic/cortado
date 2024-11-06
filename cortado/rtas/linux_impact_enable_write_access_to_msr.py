# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="cf8104ca-bd23-4652-b1f7-b63e3d92bc66",
    name="linux_impact_enable_write_access_to_msr",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="4342c282-ee21-4140-8e27-4e0f551489ef", name="MSR Write Access Enabled"),
    ],
    techniques=["T1496", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/modprobe"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "msr", "allow_writes=on"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
