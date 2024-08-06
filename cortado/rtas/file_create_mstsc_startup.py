# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata
from pathlib import Path

metadata = RtaMetadata(
    id="55750f93-0545-4222-a1fe-8b25a1c736f0",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '25224a80-5a4a-4b8a-991e-6ab390465c4f', 'rule_name': 'Lateral Movement via Startup Folder'}],
    techniques=['T1021', 'T1547', 'T1547.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    mstsc = "C:\\Users\\Public\\mstsc.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    argpath = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\'Start Menu'\\Programs\\Startup"
    _common.copy_file(EXE_FILE, mstsc)
    Path(path).mkdir(parents=True, exist_ok=True)
    file = argpath + "\\file.exe"

    _common.execute([mstsc, "/c", f"echo AAAAAAAA | Out-File {file}"], timeout=10, kill=True)
    _common.remove_files(mstsc)


if __name__ == "__main__":
    exit(main())
