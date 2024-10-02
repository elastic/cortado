# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2f19d0f2-64cb-41db-81e6-da06f9e83bcb",
    name="uac_winfw_mmc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="18a26e3e-e535-4d23-8ffa-a3cdba56d16e", name="Suspicious Parent-Child Relationship"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="65f52068-4d08-41af-9fd7-0c1a4f732494", name="UAC Bypass via Windows Firewall Snap-In Hijack"),
    ],
    techniques=["T1574", "T1055", "T1548", "T1036"],
)
def main():
    mmc = "C:\\Users\\Public\\mmc.exe"
    dllhost = "C:\\Users\\Public\\dllhost.exe"
    dccwpathdll = "C:\\Windows\\assembly\\temp\\a.dll"
    dccwpathdll2 = "C:\\Windows\\assembly\\temp\\Accessibility.ni.dll"
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    _common.copy_file(EXE_FILE, mmc)
    _common.copy_file(EXE_FILE, dllhost)

    _common.copy_file(EXE_FILE, dccwpathdll)
    _ = _common.execute_command([dllhost, "/c", f"Rename-Item {dccwpathdll} {dccwpathdll2}"], timeout_secs=10)
    _ = _common.execute_command([mmc, "/c", "echo", "WF.msc", ";powershell"], timeout_secs=2)
    _common.remove_files([mmc, dllhost, dccwpathdll2])
