# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7c4e0d1e-e80a-465a-9612-a319800390f4",
    name="exec_cmd_psexesvc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="e2f9fdf5-8076-45ad-9427-41e0e03dc9c2", name="Suspicious Process Execution via Renamed PsExec Executable"
        )
    ],
    techniques=["T1569", "T1569.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    psexesvc = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, psexesvc)

    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, psexesvc, "--set-version-string", "OriginalFilename", "psexesvc.exe"])

    _ = _common.execute_command([psexesvc], timeout_secs=2)

    _common.remove_files([rcedit, psexesvc])
