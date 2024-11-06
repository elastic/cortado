# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1843a19e-1016-4784-a175-e9fdf26f4b8f",
    name="linux_defense_evasion_lolbin_so_load",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="42c2e98b-b757-423f-ac25-8183d8c76b97", name="Shared Object Load via LoLBin"),
    ],
    techniques=["T1218", "T1574", "T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/gdb"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "cdll.LoadLibrary.so"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
