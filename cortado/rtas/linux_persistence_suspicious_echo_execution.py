# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="a2217fc5-7105-4457-98fe-1cd5f810dc1a",
name="linux_persistence_suspicious_echo_execution",    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="a13c8f01-36a5-4ad7-a282-8d297cf62860", name="Suspicious Echo Execution"),
    ],
    techniques=["T1543", "T1053", "T1037", "T1546"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/sh"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-c", "echo /dev/tcp/foo"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
