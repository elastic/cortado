# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="4aa158f6-39ed-456f-9d8a-849052cce2f5",
    name="exec_cscript_archive_args",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="816e1e39-e1a3-4935-9b7b-18395d244670", name="Windows Script Execution from Archive File"),
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="23e29d07-7584-465e-8a6d-912d9ea254a6", name="Suspicious Image Load via Windows Scripts"),
    ],
    siem_rules=[],
    techniques=["T1059", "T1059.007", "T1566", "T1566.001"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    cscript = "C:\\Users\\Public\\cscript.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, cscript)
    _common.copy_file(RENAMER, rcedit)

    _common.log("Modifying the OriginalFileName attribute")
    _common.execute([rcedit, cscript, "--set-version-string", "OriginalFilename", "cscript.exe"])

    _common.execute([cscript, "/c", "echo", "C:\\Users\\A\\Temp\\7zip"], timeout=5, kill=True)
    _common.remove_files(cscript)
