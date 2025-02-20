# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1286c142-8acc-4b58-a7c1-572870c81bc1",
    name="exec_cmd_windows_firewall_disabled",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="f63c8e3c-d396-404f-b2ea-0379d3942d73", name="Windows Firewall Disabled via PowerShell")
    ],
    techniques=["T1562", "T1562.004"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _ = _common.execute_command(
        [powershell, "/c", "echo", "Set-NetFirewallProfile", "-Enabled", "False", "-All"], timeout_secs=2
    )
