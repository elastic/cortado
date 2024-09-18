# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="aafeb270-4704-4b5f-aa1b-1286dc14c5a9",
    name="suspicious_parent_msbuild_script",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae2", name="Microsoft Build Engine Started by a Script Process"
        )
    ],
    techniques=["T1127", "T1127.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    powershell = "C:\\Users\\Public\\powershell.exe"
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    _common.copy_file(EXE_FILE, powershell)
    _common.copy_file(EXE_FILE, msbuild)

    # Execute command
    _ = _common.execute_command([powershell, "/c", msbuild], timeout_secs=2, kill=True)
    _common.remove_files([powershell, msbuild])
