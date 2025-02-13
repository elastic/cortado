# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="07edc3ea-2cf8-4a8b-aa2f-6b10f1c46838",
    name="network_connection_external_ip_lookup_non_browser",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="1d72d014-e2ab-4707-b056-9b96abe7b511", name="External IP Lookup from Non-Browser Process")
    ],
    techniques=["T1016", "T1016.001", "T1614"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _ = _common.execute_command([powershell, "/c", "iwr api.ipify.org -UseBasicParsing"], timeout_secs=10)
