# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="535959a4-5bad-44d8-9ebd-003d7ed0733c",
name="linux_persistence_rpm_netcon",    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="d20cd4ba-ff65-4e1c-8012-4241d449b16b", name="Egress Network Connection from RPM Package"),
    ],
    techniques=["T1546", "T1543", "T1574", "T1195", "T1071"],
)
def main() -> None:
    # Ensure the /var/tmp/ directory exists
    rpm_info_dir = "/var/tmp/"
    if not Path(rpm_info_dir).exists():
        log.info(f"Creating directory {rpm_info_dir}")
        Path(rpm_info_dir).mkdir(parents=True, exist_ok=True)

    # Path for the fake RPM package executable
    masquerade = str(Path(rpm_info_dir) / "rpm-tmp.rta")
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")

    log.info("Creating a fake RPM package..")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Execute the fake RPM package
    log.info("Executing the fake RPM package..")
    commands = [
        masquerade,
        "exec",
        "-c",
        "exec /var/tmp/rpm-tmp.rta netcon -h 8.8.8.8 -p 53",
    ]
    _ = _common.execute_command(commands, timeout_secs=5, shell=True)

    # Cleanup
    _common.remove_file(masquerade)
