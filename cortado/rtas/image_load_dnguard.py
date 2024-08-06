# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="1a565d0d-ac8e-487c-94cc-02aba86ad671",
    platforms=["windows"],
    endpoint_rules=[
        {
            'rule_id': 'e691d379-6d01-43cc-9f1e-ab10df48a6bc',
            'rule_name': 'Execution of a DNGUard Protected Program'
        }
    ],
    siem_rules=[],
    techniques=['T1027', 'T1027.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
PS1_FILE = _common.get_path("bin", "Invoke-ImageLoad.ps1")


@_common.requires_os(*metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\HVMRuntm.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    _common.copy_file(EXE_FILE, proc)
    _common.copy_file(user32, dll)
    _common.copy_file(PS1_FILE, ps1)

    _common.log("Loading HVMRuntm.dll into fake proc")
    _common.execute([proc, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    _common.remove_files(proc, dll, ps1)


if __name__ == "__main__":
    exit(main())
