# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f5c31db1-a376-47b3-9ba3-a946408e2bbc",
    name="uac_dism_dll_side_loading",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="18a26e3e-e535-4d23-8ffa-a3cdba56d16e", name="Suspicious Parent-Child Relationship"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="38210b91-f593-4c1c-a582-e5309c5b5168", name="UAC Bypass Attempt via DismCore DLL Side-Loading"
        ),
    ],
    siem_rules=[],
    techniques=["T1574", "T1055", "T1548", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    dism = "C:\\Users\\Public\\Dism.exe"
    dllhost = "C:\\Users\\Public\\dllhost.exe"
    dccwpathdll = "C:\\Users\\Public\\a.dll"
    dccwpathdll2 = "C:\\Users\\Public\\DismCore.dll"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, dism)
    _common.copy_file(EXE_FILE, dllhost)
    _common.copy_file(EXE_FILE, dccwpathdll)

    _ = _common.execute_command([dllhost, "/c", f"Rename-Item {dccwpathdll} {dccwpathdll2}"], timeout_secs=10)
    _ = _common.execute_command([dism, "/c", powershell], timeout_secs=2, kill=True)
    _common.remove_files([dism, dllhost, dccwpathdll2])
