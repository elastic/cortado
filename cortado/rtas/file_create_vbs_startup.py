# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7cee9313-5e55-472b-9d61-a95b0c9725d6",
    name="file_create_vbs_startup",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="f7c4dc5a-a58d-491d-9f14-9b66507121c0", name="Persistent Scripts in the Startup Directory")
    ],
    techniques=["T1547", "T1547.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    path = "C:\\Users\\Programs\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\a.vbs"
    _common.copy_file(EXE_FILE, file)

    _common.remove_files([file])
