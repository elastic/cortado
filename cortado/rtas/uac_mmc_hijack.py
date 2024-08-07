# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="99d89d71-4025-481d-80f9-efb795beca29",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="ccdf56a8-697b-497c-ab90-3aa01bfc5f9f", name="UAC Bypass via Malicious MMC Snap-In Execution"),
    ],
    siem_rules=[],
    techniques=["T1548", "T1036"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    mmc = "C:\\Users\\Public\\mmc.exe"
    msc = "C:\\Users\\Public\\a.msc"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, mmc)
    _common.copy_file(EXE_FILE, msc)

    _common.execute([mmc, "/c", "echo", "a.msc b.msc"], timeout=2, kill=True)
    _common.execute([mmc, "/c", powershell], timeout=2, kill=True)
    _common.remove_files(mmc, msc)
