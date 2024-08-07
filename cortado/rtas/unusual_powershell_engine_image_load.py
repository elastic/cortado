# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="a5d82c62-6d4e-4d31-94f2-a996c9613604",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f57505bb-a1d2-4d3b-b7b5-1d81d7bdb80e", name="Unusual PowerShell Engine ImageLoad")
    ],
    siem_rules=[],
    techniques=["T1059"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    posh = "C:\\Windows\\System32\\posh.exe"
    _common.copy_file(powershell, posh)

    _common.log("Executing renamed powershell on system32 folder")
    _common.execute([posh, "-c", "echo RTA"], timeout=10)
    _common.remove_files(posh)


