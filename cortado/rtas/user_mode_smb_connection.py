# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8ce1099f-26e7-45ea-a7a9-9ab0926a2c4a",
    name="user_mode_smb_connection",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="2fbbd139-3919-4b6b-9c50-9452b0aef005", name="Unexpected SMB Connection from User-mode Process")
    ],
    siem_rules=[],
    techniques=["T1021"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    posh = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\posh.exe"

    # Execute command
    _common.copy_file(powershell, posh)
    log.info("Testing connection to Portquiz at Port 445")
    _ = _common.execute_command(
        [
            posh,
            "/c",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "445",
        ],
        timeout_secs=10,
    )
    _common.remove_files([posh])
