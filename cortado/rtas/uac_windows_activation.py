# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9643aa7f-fe2e-46f1-b3ef-8cf07b5aaaa0",
    name="uac_windows_activation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="71ad1420-ed83-46d0-835b-63d4b2008427", name="UAC Bypass via Windows Activation Execution Hijack"
        )
    ],
    siem_rules=[],
    techniques=["T1548"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    key = "Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command"
    value = "test"
    data = "test"

    with _common.temp_registry_value(_const.REG_HKCU, key, value, data):
        pass

    changepk = "C:\\Users\\Public\\changepk.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, changepk)

    _ = _common.execute_command([changepk, "/c", powershell], timeout_secs=2)
    _common.remove_file(changepk)
