# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a555c960-08af-49fe-8889-18434a604f68",
    name="exec_cmd_workfolders",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="ad0d2742-9a49-11ec-8d6b-acde48001122", name="Signed Proxy Execution via MS Work Folders")
    ],
    techniques=["T1218"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    workfolders = "C:\\Users\\Public\\WorkFolders.exe"
    control = "C:\\Users\\Public\\control.exe"
    _common.copy_file(EXE_FILE, workfolders)
    _common.copy_file(EXE_FILE, control)

    # Execute command
    _ = _common.execute_command([workfolders, "/c", control], timeout_secs=2)
    _common.remove_files([workfolders, control])
