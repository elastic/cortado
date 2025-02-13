# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f8ffc63a-4a54-44a8-ac55-9c63e1bb584c",
    name="kerberos_netconn_file_creation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="ced93ac0-f153-402f-9239-17ae32f304e2", name="Suspicious Credential Files Creation via Kerberos"
        )
    ],
    techniques=["T1558", "T1021"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    cmd1 = "Test-NetConnection -ComputerName portquiz.net -Port 445"
    cmd2 = "echo 'aaa' > a.kirbi; rm a.kirbi"
    # Execute command
    log.info("Connecting to port 88 and creating a empty .kirbi file")
    _ = _common.execute_command([powershell, "/c", cmd1, ";", cmd2], timeout_secs=10)
