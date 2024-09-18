# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6ffcba60-acde-46e2-994a-a79ec8e07ef3",
    name="windows_script_host_file_written_exec",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="49e47c2a-307f-4591-939a-dfdae6e5156c", name="Execution of a File Written by Windows Script Host"
        ),
        RuleMetadata(
            id="83da4fac-563a-4af8-8f32-5a3797a9068e", name="Suspicious Windows Script Interpreter Child Process"
        ),
    ],
    siem_rules=[],
    techniques=["T1055", "T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    server, ip, port = _common.serve_dir_over_http()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    cscript = "C:\\Users\\Public\\cscript.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, cscript)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    log.info("Using a fake cscript to drop and execute an .exe")
    _ = _common.execute_command([cscript, "/c", cmd], timeout_secs=10)
    _ = _common.execute_command([cscript, "/c", dropped], timeout_secs=10, kill=True)
    _common.remove_file(cscript)
    _common.remove_file(dropped)
