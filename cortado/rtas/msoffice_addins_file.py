# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="97979b30-908d-4c57-a33a-f3b78e55a84a",
    name="msoffice_addins_file",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="aaa80718-1ed9-43bd-bcf7-97f2a6c93ea8", name="Persistence via Microsoft Office AddIns")
    ],
    siem_rules=[],
    techniques=["T1137"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Word\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\file.exe"

    _common.copy_file(EXE_FILE, file)
    _common.remove_file(file)
