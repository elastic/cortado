# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="4f7261bb-d298-48ec-9cdf-b8ebe05a7f1e",
    name="exec_officecmd",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="12e6ac2e-a429-4f54-abb2-eaa5713a4d06", name="Suspicious Execution via Microsoft OfficeCmd URL Handler"
        )
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    localbridge = "C:\\Users\\Public\\LocalBridge.exe"
    _common.copy_file(EXE_FILE, localbridge)

    _common.execute(
        [localbridge, "/c", "echo", "ms-officecmd.LaunchOfficeAppForResult.--gpu-launcher"], timeout=2, kill=True
    )
    _common.remove_file(localbridge)
