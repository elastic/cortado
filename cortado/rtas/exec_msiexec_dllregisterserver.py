# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="a37316f1-2828-45d2-85ea-1783bb9b9982",
    name="exec_msiexec_dllregisterserver",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="ed77616c-8f97-472b-bb15-532af004e82a", name="Suspicious DLLRegisterServer Execution via MSIEXEC"
        )
    ],
    siem_rules=[],
    techniques=["T1218", "T1218.007"],
)
def main():
    msiexec = "C:\\Windows\\System32\\msiexec.exe"

    _common.execute([msiexec, "/z"], timeout=5, kill=True)
    _common.remove_files(msiexec)
