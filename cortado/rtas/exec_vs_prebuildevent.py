# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="c4445d28-fe0f-4822-b0b0-92e188a9ca0e",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="74be6307-2d15-4c71-8072-fc606f337a51", name="Execution via MS VisualStudio Pre/Post Build Events"
        ),
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    siem_rules=[],
    techniques=["T1127", "T1127.001"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    msbuild = "C:\\Users\\Public\\msbuild.exe"
    cmd = "C:\\Users\\Public\\cmd.exe"
    _common.copy_file(EXE_FILE, cmd)
    _common.copy_file(EXE_FILE, msbuild)

    _common.execute(
        [msbuild, "/c", cmd, "/c", cmd, "echo C:\\Users\\A\\AppData\\Local\\Temp\\tmpa.exec.cmd"], timeout=10, kill=True
    )
    _common.remove_files(cmd, msbuild)
