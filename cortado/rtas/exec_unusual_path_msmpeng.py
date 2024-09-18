# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1f0afcd1-e091-4489-a750-5b0b44e69e45",
    name="exec_unusual_path_msmpeng",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="053a0387-f3b5-4ba5-8245-8002cca2bd08",
            name="Potential DLL Side-Loading via Microsoft Antimalware Service Executable",
        )
    ],
    techniques=["T1574", "T1574.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    msmpeng = "C:\\Users\\Public\\MsMpEng.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, msmpeng)

    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, msmpeng, "--set-version-string", "OriginalFilename", "MsMpEng.exe"])

    _ = _common.execute_command([msmpeng], timeout_secs=2, kill=True)

    _common.remove_files([rcedit, msmpeng])
