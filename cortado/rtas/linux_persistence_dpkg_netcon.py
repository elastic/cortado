# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="3d387400-3fc4-457f-92cd-8ba77271b348",
    name="linux_persistence_dpkg_netcon",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="947b70bb-8e01-4f1b-994d-5af9488556bb", name="Egress Network Connection from Default DPKG Directory"
        ),
    ],
    techniques=["T1546", "T1543", "T1574", "T1195", "T1071"],
)
def main() -> None:
    # Ensure the /var/lib/dpkg/info/ directory exists
    dpkg_info_dir = "/var/lib/dpkg/info/"
    if not Path(dpkg_info_dir).exists():
        log.info(f"Creating directory {dpkg_info_dir}")
        Path(dpkg_info_dir).mkdir(parents=True, exist_ok=True)

    # Path for the fake DPKG package executable
    masquerade = str(Path(dpkg_info_dir) / "rta")
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")

    log.info("Creating a fake DPKG package..")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Execute the fake DPKG package
    log.info("Executing the fake DPKG package..")
    commands = [
        masquerade,
        "chain",
        "-h",
        "8.8.8.8",
        "-p",
        "53",
        "-c",
        "/var/lib/dpkg/info/rta netcon -h 8.8.8.8 -p 53",
    ]
    _ = _common.execute_command(commands, timeout_secs=5)

    # Cleanup
    _common.remove_file(masquerade)
