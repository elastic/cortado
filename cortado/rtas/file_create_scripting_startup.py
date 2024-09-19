# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="e56f77bc-d9a7-4e02-97e2-b3056f3d4171",
    name="file_create_scripting_startup",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="440e2db4-bc7f-4c96-a068-65b78da59bde", name="Startup Persistence by a Suspicious Process")
    ],
    techniques=["T1547", "T1547.001"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    argpath = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\'Start Menu'\\Programs\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = argpath + "\\file.exe"

    _ = _common.execute_command([powershell, "/c", f"echo AAAAAAAA | Out-File {file}"], timeout_secs=10)
    _common.remove_files([file])
