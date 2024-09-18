# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


log = logging.getLogger(__name__)

@register_code_rta(
    id="7e23fa7b-1812-4abb-ab42-a2350c9a4741",
    name="file_potential_dll_hijacking",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="ddc4fa22-4675-44c0-a813-e786e638d7e0", name="Potential Initial Access via DLL Search Order Hijacking"
        )
    ],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")

    appdata = os.getenv("LOCALAPPDATA")

    if not appdata:
        raise ValueError("No value for `LOCALAPPDATA`")

    path = Path(appdata) / "\\Microsoft\\OneDrive"
    winword = "C:\\Users\\Public\\winword.exe"
    dll = path / "\\a.dll"
    _common.copy_file(exe_file, winword)

    if path.is_dir():
        _ = _common.execute_command([winword, "-c", f"New-Item -Path {dll} -Type File"], timeout_secs=10)
        _common.remove_files([dll, winword])
    else:
        path.mkdir()
        _ = _common.execute_command([winword, "-c", f"New-Item -Path {dll} -Type File"], timeout_secs=10)
        _common.remove_files([dll, winword])
        path.rmdir()
