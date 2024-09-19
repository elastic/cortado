# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)



@register_code_rta(
    id="55750f93-0545-4222-a1fe-8b25a1c736f0",
    name="file_create_mstsc_startup",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="25224a80-5a4a-4b8a-991e-6ab390465c4f", name="Lateral Movement via Startup Folder")],
    techniques=["T1021", "T1547", "T1547.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    mstsc = "C:\\Users\\Public\\mstsc.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    argpath = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\'Start Menu'\\Programs\\Startup"
    _common.copy_file(EXE_FILE, mstsc)
    Path(path).mkdir(parents=True, exist_ok=True)
    file = argpath + "\\file.exe"

    _ = _common.execute_command([mstsc, "/c", f"echo AAAAAAAA | Out-File {file}"], timeout_secs=10)
    _common.remove_files([mstsc])
