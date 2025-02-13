# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d2671cc5-87d0-4612-9e3c-0862b137d242",
    name="msoffice_wmi_imageload",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="46952f58-6741-4280-8e74-fa43f63c9604", name="WMI Image Load via Microsoft Office")
    ],
    techniques=["T1047", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
    PS1_FILE = _common.get_resource_path("bin/Invoke-ImageLoad.ps1")

    winword = "C:\\Users\\Public\\winword.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wmiutils.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    wmiprvse = "C:\\Users\\Public\\WmiPrvSE.exe"
    _common.copy_file(EXE_FILE, winword)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(EXE_FILE, wmiprvse)

    log.info("Loading wmiutils.dll into fake winword")
    _ = _common.execute_command([winword, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout_secs=10)
    _ = _common.execute_command([wmiprvse, "/c", "powershell"], timeout_secs=1)
    _common.remove_files([winword, dll, ps1])
