# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4b186cd2-eebf-4a93-b85d-ba3b3746bf50",
    name="linux_defense_evasion_proxy_execution_via_php",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="dd914805-e99b-4ff6-b445-775c53d44e10", name="Potential Proxy Execution via PHP"),
    ],
    techniques=["T1218", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/php"
    masquerade2 = "/tmp/sh"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade2)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade, "-r", masquerade2, "-c", "whoami"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    log.info("Simulation successfull!")
