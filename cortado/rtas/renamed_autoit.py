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
    techniques=["T1036"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")
    renamer = _common.get_resource_path("bin/rcedit-x64.exe")

    autoit = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    _common.copy_file(renamer, rcedit)
    _common.copy_file(exe_file, autoit)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command(
        [rcedit, autoit, "--set-version-string", "OriginalFileName", "autoitrta.exe"],
        timeout_secs=10,
    )
    _ = _common.execute_command([autoit], timeout_secs=5)

    _common.remove_files([autoit, rcedit])
