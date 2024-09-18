# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e55c13d4-ab70-4a3d-ba1e-c54156000e42",
    name="suspicious_child_solarwinds_businesslayerhost",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="93b22c0a-06a0-4131-b830-b10d5e166ff4", name="Suspicious SolarWinds Child Process")],
    techniques=["T1106", "T1195", "T1195.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    buzz = "C:\\Users\\Public\\SolarWinds.BusinessLayerHost.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, buzz)

    # Execute command
    _ = _common.execute_command([buzz, "/c", powershell], timeout_secs=2, kill=True)
    _common.remove_file(buzz)
