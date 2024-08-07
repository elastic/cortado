# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="f0340de4-e433-49a3-ba8c-de0ded32840d",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="4ed493fc-d637-4a36-80ff-ac84937e5461", name="Execution via MSSQL xp_cmdshell Stored Procedure")
    ],
    techniques=["T1059"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    sqlservr = "C:\\Users\\Public\\sqlservr.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    _common.copy_file(EXE_FILE, sqlservr)

    # Execute command
    _common.execute([sqlservr, "/c", cmd], timeout=2, kill=True)
    _common.remove_file(sqlservr)
