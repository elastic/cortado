# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="65c661e6-7a15-45c0-97ad-0635eda560ba",
    name="exec_winword_susp_parent",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="9efd977a-6d4a-4cc8-8ab3-355587b0ef69", name="Suspicious Execution via Microsoft Office Add-Ins"
        )
    ],
    siem_rules=[],
    techniques=["T1137", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    winword = "C:\\Users\\Public\\winword.exe"
    _common.copy_file(EXE_FILE, winword)

    # Execute command
    _ = _common.execute_command([powershell, "/c", winword, "/c", "echo", "doc.wll"], timeout_secs=5, kill=True)
    _common.remove_file(winword)
