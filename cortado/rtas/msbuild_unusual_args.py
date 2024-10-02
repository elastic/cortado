# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="511278ac-4996-438e-ba03-bef8f10665b5",
    name="msbuild_unusual_args",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
        RuleMetadata(id="6518cdaf-e6cd-4cf9-a51e-043117c3dbeb", name="MSBuild with Unusual Arguments"),
    ],
    techniques=["T1127", "T1218"],
)
def main():
    RENAMER = _common.get_resource_path("bin/rcedit-x64.exe")
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    msbuild = "C:\\Users\\Public\\posh.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, msbuild)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, msbuild, "--set-version-string", "OriginalFilename", "MSBuild.exe"])

    log.info("Executing modified binary with extexport.exe original file name")
    _ = _common.execute_command([msbuild, "-Version"], timeout_secs=10)

    _common.remove_files([msbuild, rcedit])
