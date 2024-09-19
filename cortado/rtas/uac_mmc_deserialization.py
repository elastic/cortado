# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1d486055-38f8-4cf3-aec1-7f4f72d73fb2",
    name="uac_mmc_deserialization",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="df7e55c9-cd36-4e33-9e82-3a54b9c84495", name="UAC Bypass via Unsafe Deserialization in Event Viewer"
        )
    ],
    siem_rules=[],
    techniques=["T1548"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")

    appdata = os.getenv("LOCALAPPDATA")

    if not appdata:
        raise _common.ExecutionError("No value for `LOCALAPPDATA` found")

    path = Path(appdata) / "\\Microsoft\\Event Viewer"
    recentfiles = path / "\\RecentViews"

    if path.is_dir():
        _common.copy_file(exe_file, recentfiles)
        _common.remove_file(recentfiles)
    else:
        path.mkdir()
        _common.copy_file(exe_file, recentfiles)
        _common.remove_file(recentfiles)
        path.rmdir()
