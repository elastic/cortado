# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0eb19c28-f82f-4f69-b11f-3b946f310e32",
    name="exec_cmd_set_casmailbox",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="ce64d965-6cb0-466d-b74f-8d2c76f47f05", name="New ActiveSyncAllowedDeviceID Added via PowerShell"
        )
    ],
    techniques=["T1098", "T1098.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _ = _common.execute_command([powershell, "/c", "echo", "Set-CASMailbox ActiveSyncAllowedDeviceIDs"], timeout_secs=5, kill=True)
