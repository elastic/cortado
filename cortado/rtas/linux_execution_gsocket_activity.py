# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b6dde7bc-4408-4a29-9c23-3c72cab3548c",
    name="linux_execution_gsocket_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="9015e5ec-a68d-4539-923d-a96d2c6227d3", name="Potential Gsocket Activity"),
    ],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/sh"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "gs-netcat"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
