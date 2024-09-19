# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5432792c-d31a-42cc-a82f-0884ea230493",
    name="file_create_ms_addins",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="f44fa4b6-524c-4e87-8d9e-a32599e4fb7c", name="Persistence via Microsoft Office AddIns")
    ],
    techniques=["T1137"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    path = "C:\\Users\\Public\\\\AppData\\Roaming\\Microsoft\\Word\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\file.xll"
    _common.copy_file(EXE_FILE, file)

    _common.remove_files([file])
