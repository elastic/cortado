# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="463e513d-1b7e-447c-a019-a340445cea3f",
    name="powershell_delete_shadow_copy",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="d99a037b-c8e2-47a5-97b9-170d076827c4", name="Volume Shadow Copy Deletion via PowerShell")
    ],
    techniques=["T1490"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _ = _common.execute_command(
        [powershell, "/c", "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"], timeout_secs=10
    )
