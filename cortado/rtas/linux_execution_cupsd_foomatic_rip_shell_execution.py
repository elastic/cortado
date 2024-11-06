# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1c088eaa-97a1-4ff7-9fa5-a6bc311e9b1e",
    name="linux_execution_cupsd_foomatic_rip_shell_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="8ccebdc1-9929-4584-ac8f-a96ee8e8c616", name="Foomatic-rip Shell Execution"),
    ],
    techniques=["T1203"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/foomatic-rip"
    masquerade2 = "/tmp/sh"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade2)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade, masquerade2, "-c", "whoami"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    log.info("Simulation successfull!")
