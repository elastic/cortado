# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="43636c0c-162b-4445-bcd0-348cbd203fa3",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="99f2327e-871f-4b8a-ae75-d1c4697aefe4", name="Renamed AutoIt Scripts Interpreter")],
    siem_rules=[],
    techniques=["T1036"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    autoit = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, autoit)

    # Execute command
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute(
        [rcedit, autoit, "--set-version-string", "OriginalFileName", "autoitrta.exe"],
        timeout=10,
    )
    _common.execute([autoit], timeout=5, kill=True)

    _common.remove_files(autoit, rcedit)
