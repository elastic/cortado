# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9e7ec69a-50cb-4bce-8ace-50e4e6f0199d",
    name="linux_execution_renice_ulimit",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="57ed0e43-643a-47f3-936e-138dc6f480da", name="Renice or Ulimit Execution"),
    ],
    techniques=["T1059"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/dev/shm/evil"

    source = _common.get_resource_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    _common.execute_command(["chmod", "+x", masquerade])

    masquerade2 = "/dev/shm/renice"
    _common.copy_file(source, masquerade2)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade2])

    commands = [masquerade, "exec", "-c", "/dev/shm/renice"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    log.info("Simulation successfull!")
