# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="7961c43d-4dd8-45ec-b237-a940bf55d114",
    name="suspicious_lineage_script",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="e7125cea-9fe1-42a5-9a05-b0792cf86f5a", name="Execution of Persistent Suspicious Program")
    ],
    techniques=["T1547", "T1547.001"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    cscript = "C:\\Users\\Public\\cscript.exe"
    explorer = "C:\\Users\\Public\\explorer.exe"
    userinit = "C:\\Users\\Public\\userinit.exe"
    winlogon = "C:\\Users\\Public\\winlogon.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, cscript)
    _common.copy_file(EXE_FILE, explorer)
    _common.copy_file(EXE_FILE, userinit)
    _common.copy_file(EXE_FILE, winlogon)
    _common.copy_file(RENAMER, rcedit)

    # Execute command
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, cscript, "--set-version-string", "OriginalFilename", "cscript.exe"])

    _common.execute([winlogon, "/c", userinit], timeout=5, kill=True)
    _common.execute([explorer, "/c", cscript], timeout=5, kill=True)
    _common.remove_files(cscript, explorer, userinit, winlogon)
