# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="41ea3472-7ec7-4c4a-baf4-b1805ba597df",
    name="suspicious_parent_cmd",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="3b47900d-e793-49e8-968f-c90dc3526aa1", name="Unusual Parent Process for cmd.exe")],
    techniques=["T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    logonui = "C:\\Users\\Public\\logonui.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    _common.copy_file(EXE_FILE, logonui)

    # Execute command
    _ = _common.execute_command([logonui, "/c", cmd], timeout_secs=2)
    _common.remove_file(logonui)
