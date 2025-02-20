# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8fb34501-1774-4618-be8e-9db6294445ab",
    name="suspicious_parent_msbuild_explorer",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae3", name="Microsoft Build Engine Started by a System Process"
        )
    ],
    techniques=["T1127", "T1127.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    explorer = "C:\\Users\\Public\\explorer.exe"
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    _common.copy_file(EXE_FILE, explorer)
    _common.copy_file(EXE_FILE, msbuild)

    # Execute command
    _ = _common.execute_command([explorer, "/c", msbuild], timeout_secs=2)
    _common.remove_files([explorer, msbuild])
