# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="810554c9-fe55-4fdd-8127-e753ae448d52",
    name="suspicious_child_solarwindsdiagnostics",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="d72e33fc-6e91-42ff-ac8b-e573268c5a87", name="Command Execution via SolarWinds Process")
    ],
    techniques=["T1059", "T1195", "T1195.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    solarwindsdiagnostics = "C:\\Users\\Public\\solarwindsdiagnostics.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, solarwindsdiagnostics)

    # Execute command
    _ = _common.execute_command([solarwindsdiagnostics, "/c", powershell], timeout_secs=2)
    _common.remove_file(solarwindsdiagnostics)
