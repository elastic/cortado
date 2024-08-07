# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="465eb9a9-2f8b-458b-9ea4-e50912ce1b89",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae4", name="Microsoft Build Engine Using an Alternate Name")
    ],
    techniques=["T1036", "T1036.003"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    msbuild = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, msbuild)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, msbuild, "--set-version-string", "OriginalFilename", "MSBuild.exe"])

    _common.execute([msbuild], timeout=2, kill=True)

    _common.remove_files(rcedit, msbuild)
