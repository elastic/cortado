# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4b85db7b-b7e7-45d1-94de-210587e6d947",
    name="network_connection_download_powershell",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="33f306e8-417c-411b-965c-c2812d6d3f4d", name="Remote File Download via PowerShell")],
    techniques=["T1105", "T1059", "T1059.001"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"

    # Execute command
    _ = _common.execute_command(
        [powershell, "/c", f"Test-NetConnection -ComputerName google.com -Port 443 | Out-File {fake_exe}"],
        timeout_secs=10,
    )
    _common.remove_file(fake_exe)
