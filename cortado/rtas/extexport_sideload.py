# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="bbbfc3e3-e1ba-45ad-9d30-cbbe115a0c6c",
    name="extexport_sideload",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="e13a65b7-f46f-4c7f-85cf-7e59170071fa", name="Execution via Internet Explorer Exporter"),
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
    ],
    techniques=["T1218"],
)
def main():
    RENAMER = _common.get_resource_path("bin/rcedit-x64.exe")
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    dll = "C:\\Users\\Public\\sqlite3.dll"
    posh = "C:\\Users\\Public\\posh.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, dll)
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, posh, "--set-version-string", "OriginalFilename", "extexport.exe"])

    log.info("Executing modified binary with extexport.exe original file name")
    _ = _common.execute_command([posh], timeout_secs=10)

    _common.remove_files([dll, posh, rcedit])
