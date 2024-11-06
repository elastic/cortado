# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="aed2d3be-94d1-4e19-80dd-6412b336e827",
    name="linux_defense_evasion_proxy_execution_via_sysctl",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="268ffea4-fc13-4ab5-a473-07d10255ea8d", name="Potential Proxy Execution via Sysctl"),
    ],
    techniques=["T1218", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/sysctl"
    masquerade2 = "/tmp/sh"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade2)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade, masquerade, "kernel.core_pattern=/bin/sh -c"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    log.info("Simulation successfull!")
