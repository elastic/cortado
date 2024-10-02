# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0debe15f-1c9b-4ff8-9e4c-478647ca45e2",
    name="file_html_smuggling",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4415ab60-7cff-41dc-b3f0-939bd22c1810", name="Suspicious File Delivery via HTML Smuggling")
    ],
    techniques=["T1027", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    userprofile = os.getenv("USERPROFILE")
    partial = f"{userprofile}\\Downloads\\a.partial"
    file = f"{userprofile}\\Downloads\\a.iso"
    explorer = "C:\\Users\\Public\\explorer.exe"
    chrome = "C:\\Users\\Public\\chrome.exe"
    _common.copy_file(EXE_FILE, explorer)
    _common.copy_file(EXE_FILE, chrome)

    # Execute command
    _ = _common.execute_command(
        [
            explorer,
            "/c",
            chrome,
            "--single-argument",
            f"{userprofile}\\Downloads\\a.html",
        ],
        timeout_secs=10,
    )
    _ = _common.execute_command([chrome, "/c", f"New-Item -Path {partial} -Type File"], timeout_secs=10)
    _ = _common.execute_command([chrome, "/c", f"Rename-Item {partial} {file}"], timeout_secs=10)
    _common.remove_files([explorer, chrome, file])
