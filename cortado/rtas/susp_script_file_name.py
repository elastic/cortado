# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="84579cd0-2b30-4846-9b4e-9663ae2c400a",
    name="susp_script_file_name",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="8c69476a-d8ea-46da-8052-6a4f9254125c", name="Suspicious Windows Script File Name"),
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="f0630213-c4c4-4898-9514-746395eb9962", name="Script Execution via Microsoft HTML Application"),
    ],
    siem_rules=[],
    techniques=["T1036", "T1218", "T1566", "T1059"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")
    renamer = _common.get_resource_path("bin/rcedit-x64.exe")

    mshta = "C:\\Users\\Public\\mshta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    _common.copy_file(renamer, rcedit)
    _common.copy_file(exe_file, mshta)

    cmd = "ls ~\\Downloads\\*.pdf.js"
    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command(
        [rcedit, mshta, "--set-version-string", "OriginalFileName", "mshta.exe"],
        timeout_secs=10,
    )
    _ = _common.execute_command([mshta, "/c", cmd], timeout_secs=5)

    _common.remove_files([mshta, rcedit])
