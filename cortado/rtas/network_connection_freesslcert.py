# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9261a9ca-53ed-483c-967a-3f7a8f93e0ea",
    name="network_connection_freesslcert",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="e3cf38fa-d5b8-46cc-87f9-4a7513e4281d",
            name="Connection to Commonly Abused Free SSL Certificate Providers",
        )
    ],
    techniques=["T1573"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _ = _common.execute_command(
        [powershell, "/c", "Test-NetConnection -ComputerName www.letsencrypt.org -Port 443"], timeout_secs=10
    )
