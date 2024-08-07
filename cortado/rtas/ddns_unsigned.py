# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="9e85eb9f-ee9e-4c73-8a83-14dd29a5aa80",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="75b80e66-90d0-4ab6-9e6b-976f7d690906", name="Connection to Dynamic DNS Provider by an Unsigned Binary"
        )
    ],
    siem_rules=[],
    techniques=["T1071"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    _common.log("Using PowerShell to connect to a DDNS provider website")
    _common.execute([posh, "/c", "iwr", "https://www.noip.com", "-UseBasicParsing"], timeout=10)
    _common.remove_file(posh)
