# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="57d4d7f4-03a6-43d3-a5af-9ac706b2eedf",
    name="exec_cmd_clear_history",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="b5877334-677f-4fb9-86d5-a9721274223b", name="Clearing Windows Console History")],
    techniques=["T1070", "T1070.003"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _common.execute([powershell, "/c", "Clear-History"], timeout=10)
