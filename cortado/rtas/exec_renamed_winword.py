# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c5a8bbf2-0920-40ee-a08f-f897c2895eba",
    name="exec_renamed_winword",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="1160dcdb-0a0a-4a79-91d8-9b84616edebd", name="Potential DLL SideLoading via Trusted Microsoft Programs"
        )
    ],
    techniques=["T1036"],
)
def main():
    exe_file = _common.get_resource_path("bin/renamed_posh.exe")
    renamer_exe = _common.get_resource_path("bin/rcedit-x64.exe")

    winword = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    _common.copy_file(renamer_exe, rcedit)
    _common.copy_file(exe_file, winword)

    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, winword, "--set-version-string", "OriginalFilename", "WinWord.exe"])
    _ = _common.execute_command(winword, shell=True, timeout_secs=2)

    _common.remove_files([rcedit, winword])
