# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="00a75607-9f1d-45c1-a9d8-41229cdb561f",
    name="linux_execution_cupsd_foomatic_rip_suspicious_child_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="7c4d6361-3e7f-481a-9313-d1d1c0e5a3a9", name="Suspicious Execution from Foomatic-rip or Cupsd Parent"
        ),
    ],
    techniques=["T1203"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/foomatic-rip"

    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "/dev/tcp"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
