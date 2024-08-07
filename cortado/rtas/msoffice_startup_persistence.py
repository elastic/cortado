# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="ea9a54fe-62ed-4825-b302-0ebbee22233f",
    name="msoffice_startup_persistence",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="2b8ea430-897d-486c-85a8-add9d7072ff3", name="Microsoft Office Process Setting Persistence via Startup"
        )
    ],
    siem_rules=[],
    techniques=["T1547", "T1566"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    powershell = "C:\\Users\\Public\\posh.exe"
    temp = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp_persist.exe"
    binary = "C:\\Users\\Public\\winword.exe"
    _common.copy_file(EXE_FILE, powershell)
    _common.copy_file(powershell, binary)

    # Execute command
    _common.log("Writing to startup folder using fake winword")
    _common.execute([binary, "/c", f"Copy-Item {powershell} '{temp}'"])

    _common.remove_files(binary, temp)
