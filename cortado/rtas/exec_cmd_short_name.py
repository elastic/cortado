# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f62ebacb-5d53-4f74-ae72-b64b8b6c899f",
    name="exec_cmd_short_name",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="17c7f6a5-5bc9-4e1f-92bf-13632d24384d", name="Suspicious Execution - Short Program Name")
    ],
    techniques=["T1036", "T1036.003"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    rta = "C:\\Users\\Public\\a.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, rta)

    log.info("Modifying the OriginalFileName attribute")
    _ = _common.execute_command([rcedit, rta, "--set-version-string", "OriginalFilename", "rta.exe"])

    _ = _common.execute_command([rta], timeout_secs=2)

    _common.remove_files([rcedit, rta])
