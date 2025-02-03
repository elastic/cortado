# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="05170b5b-8030-4acd-b7c1-d6d1fe8bbd2d",
    name="linux_defense_evasion_process_injection_via_dd",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="38108046-32a6-407f-b5fd-6943ffdcdab0", name="Potential Process Injection via dd"),
    ],
    techniques=["T1620", "T1574", "T1106"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/dd"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "if=foo", "of=/proc/pid/mem"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
