# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="95d34e55-789d-40bf-9988-dbb803c2d066",
    name="ddns_lolbas",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="fb6939a2-1b54-428c-92a2-3a831585af2a",
            name="Connection to Dynamic DNS Provider by a Signed Binary Proxy",
        )
    ],
    techniques=["T1218", "T1071"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    log.info("Using PowerShell to connect to a DDNS provider website")
    _ = _common.execute_command(
        [powershell, "/c", "iwr", "https://www.noip.com", "-UseBasicParsing"],
        timeout_secs=10,
    )
