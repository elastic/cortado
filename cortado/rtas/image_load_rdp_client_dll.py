# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="eb06a33e-bc80-412b-8ae8-f45af6682293",
    name="image_load_rdp_client_dll",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="71c5cb27-eca5-4151-bb47-64bc3f883270", name="Suspicious RDP ActiveX Client Loaded")],
    techniques=["T1021"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")

    proc = "C:\\Users\\Public\\proc.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\mstscax.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    wmiprvse = "C:\\Users\\Public\\WmiPrvSE.exe"
    _common.copy_file(EXE_FILE, proc)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(EXE_FILE, wmiprvse)

    log.info("Loading mstscax.dll into proc")
    _ = _common.execute_command([proc, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)
    _common.remove_files([proc, dll, ps1])
