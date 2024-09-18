# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0b3a3f97-f09e-4a42-b592-6be2b5467c08",
    name="exec_cmd_netsh_remotedesktop",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="074464f9-f30d-4029-8c03-0ed237fffec7", name="Remote Desktop Enabled in Windows Firewall by Netsh"
        )
    ],
    techniques=["T1562", "T1562.004"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    netsh = "C:\\Users\\Public\\netsh.exe"
    _common.copy_file(EXE_FILE, netsh)

    # Execute command
    _ = _common.execute_command([netsh, "/c", "echo", "RemoteDesktop", "enable"], timeout_secs=2)
    _common.remove_file(netsh)
