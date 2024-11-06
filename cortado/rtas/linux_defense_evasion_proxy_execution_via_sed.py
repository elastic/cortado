# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="49b9a7c8-5974-4ed3-bba0-12ab02d9b8bc",
    name="linux_defense_evasion_proxy_execution_via_sed",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="272cf3e7-fd3f-442b-a781-f9e864fb1d4c", name="Potential Proxy Execution via Sed"),
    ],
    techniques=["T1218", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/sed"
    masquerade2 = "/tmp/sh"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade2)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade, "-n", masquerade, "-c", "whoami"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    log.info("Simulation successfull!")
