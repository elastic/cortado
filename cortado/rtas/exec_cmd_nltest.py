# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="c5b8e9c5-59c6-4316-8e73-cd4f5a9a2761",
    name="exec_cmd_nltest",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="84da2554-e12a-11ec-b896-f661ea17fbcd", name="Enumerating Domain Trusts via NLTEST.EXE")
    ],
    techniques=["T1482"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _common.execute([powershell, "/c", "nltest.exe /DCLIST:$env:USERDNSDOMAIN"], timeout=10)
