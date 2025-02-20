# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7253d78c-8a68-4073-b20a-fbab9d4daf23",
    name="network_connection_download_script_interpreter",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="1d276579-3380-4095-ad38-e596a01bc64f", name="Remote File Download via Script Interpreter")
    ],
    techniques=["T1105"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    wscript = "C:\\Users\\Public\\wscript.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"
    _common.copy_file(EXE_FILE, wscript)

    # Execute command
    _ = _common.execute_command(
        [wscript, "/c", f"Test-NetConnection -ComputerName google.com -Port 443 | Out-File {fake_exe}"], timeout_secs=10
    )
    _common.remove_files([fake_exe, wscript])
