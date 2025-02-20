# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e8612e97-2df7-4e85-94ee-e61bc58c6479",
    name="uac_wsreset",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="11c67af9-9599-4800-9e84-bd38f2a51581", name="UAC Bypass via WSReset Execution Hijack")
    ],
    techniques=["T1548"],
)
def main():
    key = "Software"
    value = "ms-windows-store"
    data = "test"

    exe_file = _common.get_resource_path("bin/renamed_posh.exe")

    with _common.temp_registry_value(_const.REG_HKCU, key, value, data):
        pass

    wsreset = "C:\\Users\\Public\\wsreset.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(exe_file, wsreset)

    _ = _common.execute_command([wsreset, "/c", powershell], timeout_secs=2)
    _common.remove_file(wsreset)
