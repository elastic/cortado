# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="64a7cd38-767f-4d46-9350-feb585a32c18",
    name="rundll32_unusual_dll_extension",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="76da5dca-ffe5-4756-85ba-3ac2e6ccf623", name="Unusual DLL Extension Loaded by Rundll32 or Regsvr32"
        ),
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")

    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\a.rta"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    _common.copy_file(EXE_FILE, rundll32)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)

    # Execute command

    log.info("Loading a.rta into fake rundll32")
    _ = _common.execute_command([rundll32, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)

    _common.remove_files([rundll32, dll, ps1])
