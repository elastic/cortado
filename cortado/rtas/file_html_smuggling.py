# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common

import os


@register_code_rta(
    id="0debe15f-1c9b-4ff8-9e4c-478647ca45e2",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4415ab60-7cff-41dc-b3f0-939bd22c1810", name="Suspicious File Delivery via HTML Smuggling")
    ],
    siem_rules=[],
    techniques=["T1027", "T1566"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    userprofile = os.getenv("USERPROFILE")
    partial = f"{userprofile}\\Downloads\\a.partial"
    file = f"{userprofile}\\Downloads\\a.iso"
    explorer = "C:\\Users\\Public\\explorer.exe"
    chrome = "C:\\Users\\Public\\chrome.exe"
    _common.copy_file(EXE_FILE, explorer)
    _common.copy_file(EXE_FILE, chrome)

    # Execute command
    _common.execute(
        [
            explorer,
            "/c",
            chrome,
            "--single-argument",
            f"{userprofile}\\Downloads\\a.html",
        ],
        timeout=10,
        kill=True,
    )
    _common.execute([chrome, "/c", f"New-Item -Path {partial} -Type File"], timeout=10)
    _common.execute([chrome, "/c", f"Rename-Item {partial} {file}"], timeout=10)
    _common.remove_files(explorer, chrome, file)


if __name__ == "__main__":
    exit(main())
