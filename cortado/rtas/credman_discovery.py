# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d12e0abb-017f-4321-adf2-20843f62b55d",
    name="credman_discovery",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="cc60be0e-2c6c-4dc9-9902-e97103ff8df9", name="Potential Discovery of Windows Credential Manager Store"
        )
    ],
    techniques=["T1555"],
)
def main():
    appdata = os.getenv("LOCALAPPDATA")
    credmanfile = f"{appdata}\\Microsoft\\Credentials\\a.txt"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command

    _ = _common.execute_command([powershell, "/c", "echo AAAAAAAAAA >", credmanfile], timeout_secs=10)
    log.info("Cat the contents of a sample file in credman folder")
    _ = _common.execute_command([powershell, "/c", "cat", credmanfile], timeout_secs=10)
    _common.remove_file(credmanfile)
