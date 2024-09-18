# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="99180561-08ad-42e7-bcda-078af280ad9c",
    name="exec_sliver_posh",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="14626cac-eb09-4e52-81f1-f87975e8f5ae", name="Potential Execution via Sliver Framework")
    ],
    siem_rules=[],
    techniques=["T1059", "T1059.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _ = _common.execute_command(
        [powershell, "-NoExit", "-Command", "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8"], timeout_secs=5, kill=True
    )
