# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="b279f4c3-2269-4557-b267-68dc2f88019b",
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
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    excel = "C:\\Users\\Public\\excel.exe"
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    _common.copy_file(EXE_FILE, excel)
    _common.copy_file(EXE_FILE, msbuild)

    # Execute command
    _common.execute([excel, "/c", msbuild], timeout=2, kill=True)
    _common.remove_files(excel, msbuild)
