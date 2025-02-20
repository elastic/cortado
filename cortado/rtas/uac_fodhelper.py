# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a67586fd-cceb-4fb9-bf0e-d355b9e8921a",
    name="uac_fodhelper",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b5c0058e-2bca-4ed5-84b3-4e017c039c57", name="UAC Bypass via FodHelper Execution Hijack")
    ],
    techniques=["T1548"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    key = "Software\\Classes\\ms-settings\\shell\\open\\command"
    value = "test"
    data = "test"

    with _common.temp_registry_value(_const.REG_HKCU, key, value, data):
        pass

    fodhelper = "C:\\Users\\Public\\fodhelper.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, fodhelper)

    _ = _common.execute_command([fodhelper, "/c", powershell], timeout_secs=2)
    _common.remove_file(fodhelper)
