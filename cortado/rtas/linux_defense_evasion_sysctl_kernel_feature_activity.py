# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a33dd7f2-65b0-49f3-b172-8830e70577f5",
    name="linux_defense_evasion_sysctl_kernel_feature_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="dbbd7fb0-8b29-4c96-901d-166dff728a3b", name="Suspicious Kernel Feature Activity"),
    ],
    techniques=["T1562", "T1553", "T1082"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/sysctl"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "--write", "/proc/sys/kernel/yama/ptrace_scope"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
