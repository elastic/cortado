# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b279f4c3-2269-4557-b267-68dc2f88019b",
    name="suspicious_parent_msbuild_office",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="c5dc3223-13a2-44a2-946c-e9dc0aa0449c", name="Microsoft Build Engine Started by an Office Application"
        )
    ],
    techniques=["T1127", "T1127.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    excel = "C:\\Users\\Public\\excel.exe"
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    _common.copy_file(EXE_FILE, excel)
    _common.copy_file(EXE_FILE, msbuild)

    # Execute command
    _ = _common.execute_command([excel, "/c", msbuild], timeout_secs=2)
    _common.remove_files([excel, msbuild])
