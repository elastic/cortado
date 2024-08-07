# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="2cd02bee-6774-4b93-a632-995462440371",
    name="image_load_script_interpreter_wmiutils",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="b64b183e-1a76-422d-9179-7b389513e74d", name="Windows Script Interpreter Executing Process via WMI"
        )
    ],
    techniques=["T1566", "T1566.001"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")

    cscript = "C:\\Users\\Public\\cscript.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wmiutils.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    wmiprvse = "C:\\Users\\Public\\WmiPrvSE.exe"
    _common.copy_file(EXE_FILE, cscript)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)
    _common.copy_file(EXE_FILE, wmiprvse)

    _common.log("Loading wmiutils.dll into fake cscript")
    _common.execute([cscript, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    _common.execute([wmiprvse, "/c", cscript], timeout=1, kill=True)
    _common.remove_files(cscript, dll, ps1)
