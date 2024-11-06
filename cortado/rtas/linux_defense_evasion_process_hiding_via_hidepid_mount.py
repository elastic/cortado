# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d174a1f4-a090-466a-a595-6881bd20eb33",
    name="linux_defense_evasion_process_hiding_via_hidepid_mount",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="03195b53-de40-4a18-b727-6fb7ac3f94b7", name="Defense Evasion via Hidepid Mount"),
    ],
    techniques=["T1564", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/mount"
    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-o", "hidepid=2"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
