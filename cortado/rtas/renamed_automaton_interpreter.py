# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8c128a2b-fa7b-4bfc-9ec9-934395460420",
    name="renamed_automaton_interpreter",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="92d720dd-93b2-49e0-b68a-d5d6acbe4910", name="Renamed Windows Automaton Script Interpreter")
    ],
    techniques=["T1036"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")
    renamer = _common.get_resource_path("bin/rcedit-x64.exe")

    autohotkey = "C:\\Users\\Public\\notaut0hotkey.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(exe_file, autohotkey)
    _common.copy_file(renamer, rcedit)

    # Execute command
    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command(
        [
            rcedit,
            autohotkey,
            "--set-version-string",
            "OriginalFilename",
            "AutoHotkey.exe",
        ]
    )

    _ = _common.execute_command(autohotkey, shell=True, timeout_secs=10)

    _common.remove_files([autohotkey, rcedit])
