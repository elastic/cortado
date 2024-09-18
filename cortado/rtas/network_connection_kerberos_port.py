# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b7ed774f-f5e8-49bd-995a-a705c979d88f",
    name="network_connection_kerberos_port",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="897dc6b5-b39f-432a-8d75-d3730d50c782", name="Kerberos Traffic from Unusual Process")],
    techniques=["T1558"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _ = _common.execute_command([powershell, "/c", "Test-NetConnection -ComputerName portquiz.net -Port 88"], timeout_secs=5)
