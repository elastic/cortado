# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="eb1ecbae-a7d0-4beb-89fe-fbf2db0edce3",
    name="suspicious_parent_sc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="e8571d5f-bea1-46c2-9f56-998de2d3ed95", name="Service Control Spawned via Script Interpreter")
    ],
    techniques=["T1021"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    sc = "C:\\Users\\Public\\sc.exe"
    _common.copy_file(EXE_FILE, sc)

    _ = _common.execute_command([powershell, "/c", sc, "echo", "create"], timeout_secs=5)
    _common.remove_files([sc])
