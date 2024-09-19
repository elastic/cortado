# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="43636c0c-162b-4445-bcd0-348cbd203fa3",
    name="renamed_autoit",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="99f2327e-871f-4b8a-ae75-d1c4697aefe4", name="Renamed AutoIt Scripts Interpreter")],
    siem_rules=[],
    techniques=["T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    autoit = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, autoit)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command(
        [rcedit, autoit, "--set-version-string", "OriginalFileName", "autoitrta.exe"],
        timeout_secs=10,
    )
    _ = _common.execute_command([autoit], timeout_secs=5)

    _common.remove_files([autoit, rcedit])
