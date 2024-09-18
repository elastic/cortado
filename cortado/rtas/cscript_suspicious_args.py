# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5a2a5c20-73f6-4a08-a767-95d242b52708",
    name="cscript_suspicious_args",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="ffbab5db-73ae-42fd-a33f-36bf649f41cc", name="Suspicious Windows Script Process Execution"),
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    cscript = "C:\\Users\\Public\\cscript.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, cscript)
    _common.copy_file(RENAMER, rcedit)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, cscript, "--set-version-string", "OriginalFilename", "cscript.exe"])

    cmd = "echo {16d51579-a30b-4c8b-a276-0ff4dc41e755}; iwr google.com -UseBasicParsing"
    log.info("Simulating a suspicious command line and making a web request")
    _ = _common.execute_command([cscript, "-c", cmd], timeout_secs=10)

    _common.remove_files([cscript, rcedit])
