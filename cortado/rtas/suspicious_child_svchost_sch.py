# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6df14bf3-6153-4ff2-aa0f-f91f2aa06b7b",
    name="suspicious_child_svchost_sch",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c", name="Potential Masquerading as SVCHOST"),
    ],
    siem_rules=[
        RuleMetadata(id="5d1d6907-0747-4d5d-9b24-e4a18853dc0a", name="Suspicious Execution via Scheduled Task")
    ],
    techniques=["T1053", "T1053.005", "T1036", "T1036.004"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    svchost = "C:\\Users\\Public\\svchost.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, svchost)

    _ = _common.execute_command([svchost, "/c", "echo", "schedule", f";{powershell}", "C:\\Users\\A"], timeout_secs=5)
    _common.remove_files([svchost])
