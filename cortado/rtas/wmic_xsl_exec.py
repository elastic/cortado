# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

log = logging.getLogger(__name__)


@register_code_rta(
    id="b9d5427a-33c4-4b1d-838d-f47c5f3b0b43",
    name="wmic_xsl_exec",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="18371ec4-ee2f-465b-8757-ee726914006c", name="Suspicious WMIC XSL Script Execution"),
    ],
    techniques=["T1220", "T1047", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")

    wmic = "C:\\Users\\Public\\wmic.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\jscript.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    _common.copy_file(EXE_FILE, wmic)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)

    log.info("Loading jscript.dll into fake wmic")
    _ = _common.execute_command(
        [wmic, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}; echo /format:"],
        timeout_secs=10,
    )

    _common.remove_files([wmic, dll, ps1])
