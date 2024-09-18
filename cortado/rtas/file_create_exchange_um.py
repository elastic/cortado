# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="29eb99a6-14cc-4d37-81dd-c2e78cda8c74",
    name="file_create_exchange_um",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="6cd1779c-560f-4b68-a8f1-11009b27fe63", name="Microsoft Exchange Server UM Writing Suspicious Files"
        )
    ],
    techniques=["T1190"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    proc = "C:\\Users\\Public\\UMWorkerProcess.exe"
    path = "C:\\Users\\Public\\Microsoft\\Exchange Server Test\\FrontEnd\\HttpProxy\\owa\\auth\\"
    argpath = "C:\\Users\\Public\\Microsoft\\'Exchange Server Test'\\FrontEnd\\HttpProxy\\owa\\auth\\"
    _common.copy_file(EXE_FILE, proc)
    Path(path).mkdir(parents=True, exist_ok=True)
    file = argpath + "\\shell.php"

    _ = _common.execute_command([proc, "/c", f"echo AAAAAAAA | Out-File {file}"], timeout_secs=10, kill=True)
    _common.remove_files([proc])
