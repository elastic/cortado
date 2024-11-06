# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4e6ded7e-23cb-460c-8a5b-21c5e5e8d6e8",
    name="linux_defense_evasion_process_masquerading_via_exec",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="e6669bc3-cb75-4fb3-91e0-ddaa06dd59b2", name="Potential Process Masquerading via Exec"),
    ],
    techniques=["T1564", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "[foo]"
    masquerade2 = "/tmp/sh"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade2)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade2, masquerade]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    log.info("Simulation successfull!")
