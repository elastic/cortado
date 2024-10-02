# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="edb804d6-85df-4dca-a521-1b6dfee9f354",
    name="file_susp_browser_extension",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7df7fca3-8a91-4a54-9799-0478a90ae326", name="Suspicious Browser Files Modification")
    ],
    techniques=["T1176", "T1112"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    proc = "C:\\Users\\Public\\proc.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Mozilla\\Test\\Profiles\\AdefaultA"
    file = path + "\\extensions.json"
    _common.copy_file(EXE_FILE, proc)
    Path(path).mkdir(parents=True, exist_ok=True)

    _ = _common.execute_command([proc, "/c", f"Copy-Item {EXE_FILE} {file}"], timeout_secs=10)
    _common.remove_files([proc, file])
