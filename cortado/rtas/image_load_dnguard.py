# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1a565d0d-ac8e-487c-94cc-02aba86ad671",
    name="image_load_dnguard",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="e691d379-6d01-43cc-9f1e-ab10df48a6bc", name="Execution of a DNGUard Protected Program")
    ],
    techniques=["T1027", "T1027.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")

    proc = "C:\\Users\\Public\\proc.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\HVMRuntm.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    _common.copy_file(EXE_FILE, proc)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)

    log.info("Loading HVMRuntm.dll into fake proc")
    _ = _common.execute_command([proc, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)
    _common.remove_files([proc, dll, ps1])
