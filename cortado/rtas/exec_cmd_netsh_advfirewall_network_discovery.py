# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5b52f7e5-e2bc-4a2d-82bd-2e844c081519",
    name="exec_cmd_netsh_advfirewall_network_discovery",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="8b4f0816-6a65-4630-86a6-c21c179c0d09", name="Enable Host Network Discovery via Netsh")
    ],
    techniques=["T1562", "T1562.004"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    netsh = "C:\\Users\\Public\\netsh.exe"
    _common.copy_file(EXE_FILE, netsh)

    # Execute command
    _ = _common.execute_command(
        [netsh, "/c", "echo", "advfirewall", "group=Network Discovery", "enable=Yes"], timeout_secs=2
    )
    _common.remove_file(netsh)
