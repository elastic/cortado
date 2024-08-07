# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="0885b643-a199-4453-95e0-be0d1f29aafc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="547636af-cad2-4be0-a74e-613c7bb86664", name="Suspicious Execution from MSSQL Service")
    ],
    siem_rules=[],
    techniques=["T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    sqlserver = "C:\\Users\\Public\\sqlserver.exe"
    _common.copy_file(EXE_FILE, sqlserver)

    # Execute command
    _common.execute([sqlserver, "/c", powershell], timeout=10, kill=True)
    _common.remove_file(sqlserver)


