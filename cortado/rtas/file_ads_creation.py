# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="ffddb3f7-75ac-49e8-9042-ae1bf5c199e8",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="71bccb61-e19b-452f-b104-79a60e546a95", name="Unusual File Creation - Alternate Data Stream")
    ],
    techniques=["T1564", "T1564.004"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    exe = "C:\\Users\\Public\\a.exe"
    _common.copy_file(EXE_FILE, exe)

    # Execute command
    _common.execute([powershell, "/c", f"Set-Content -Stream RtaTest -value Heyo -Path {exe}"], timeout=10)
    _common.remove_files(exe)
