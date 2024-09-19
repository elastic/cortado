# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2730b84c-9e39-4647-ba96-0b438aca9575",
    name="exec_cmd_set_mppreference",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="c8cccb06-faf2-4cd5-886e-2c9636cfcb87",
            name="Disabling Windows Defender Security Settings via PowerShell",
        ),
        RuleMetadata(
            id="2c17e5d7-08b9-43b2-b58a-0270d65ac85b", name="Windows Defender Exclusions Added via PowerShell"
        ),
    ],
    techniques=["T1562", "T1562.001", "T1562.006", "T1059", "T1059.001"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _ = _common.execute_command(
        [powershell, "/c", "Set-MpPreference", "-ExclusionPath", f"{powershell}"], timeout_secs=10
    )
    _ = _common.execute_command([powershell, "/c", f"Remove-MpPreference -ExclusionPath {powershell}"], timeout_secs=10)
