# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b8dcb997-e099-472e-8f2f-15a80c8dfe1a",
    name="file_script_startup_folder",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="dec8781c-ef73-4037-9684-ef28c0322fa4", name="Script File Written to Startup Folder"),
        RuleMetadata(
            id="30a90136-7831-41c3-a2aa-1a303c1186ac", name="Unusual File Written or Modified in Startup Folder"
        ),
    ],
    techniques=["T1547", "T1547.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    proc = "C:\\Users\\Public\\proc.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\'Start Menu'\\Programs\\Startup\\"
    file = path + "\\a.js"
    _common.copy_file(EXE_FILE, proc)
    Path(path).mkdir(parents=True, exist_ok=True)

    _ = _common.execute_command([proc, "/c", f"Copy-Item {EXE_FILE} {file}"], timeout_secs=10)
    _common.remove_files([proc, file])
