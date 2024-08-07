# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="511278ac-4996-438e-ba03-bef8f10665b5",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
        RuleMetadata(id="6518cdaf-e6cd-4cf9-a51e-043117c3dbeb", name="MSBuild with Unusual Arguments"),
    ],
    siem_rules=[],
    techniques=["T1127", "T1218"],
)

RENAMER = _common.get_path("bin", "rcedit-x64.exe")
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    msbuild = "C:\\Users\\Public\\posh.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, msbuild)

    # Execute command
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, msbuild, "--set-version-string", "OriginalFilename", "MSBuild.exe"])

    _common.log("Executing modified binary with extexport.exe original file name")
    _common.execute([msbuild, "-Version"], timeout=10, kill=True)

    _common.remove_files(msbuild, rcedit)


