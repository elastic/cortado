# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0885b643-a199-4453-95e0-be0d1f29aafc",
    name="exec_sqlserver_suspicious_child",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="547636af-cad2-4be0-a74e-613c7bb86664", name="Suspicious Execution from MSSQL Service")
    ],
    techniques=["T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    sqlserver = "C:\\Users\\Public\\sqlserver.exe"
    _common.copy_file(EXE_FILE, sqlserver)

    # Execute command
    _ = _common.execute_command([sqlserver, "/c", powershell], timeout_secs=10)
    _common.remove_file(sqlserver)
