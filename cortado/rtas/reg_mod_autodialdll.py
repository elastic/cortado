# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="32462f3e-d5af-4ef9-8260-aa9fbeb6e117",
    name="reg_mod_autodialdll",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="2ffc3943-8100-4f77-9c8f-e8f9e185604b", name="Persistence via AutodialDLL Registry Modification"
        )
    ],
    siem_rules=[],
    techniques=["T1112"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    key = "SYSTEM\\ControlSet001\\Services\\WinSock2\\Parameters"
    value = "AutodialDLL"
    data = "RTA"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
