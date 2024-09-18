# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="33f20563-7d1b-46a4-8644-a563f2488120",
    name="uac_mmc_net_core_profiler",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="28996098-b9be-4aa8-a1f3-4923c84b2649", name="UAC Bypass Attempt via MMC DLL Search Order Hijacking"
        ),
    ],
    siem_rules=[],
    techniques=["T1574", "T1548", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    key = "Environment"
    value = "COR_PROFILER_PATH"
    data = "temp.dll"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass

    mmc = "C:\\Users\\Public\\mmc.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, mmc)

    _ = _common.execute_command([mmc, "/c", powershell], timeout_secs=2, kill=True)
    _common.remove_files([mmc])
