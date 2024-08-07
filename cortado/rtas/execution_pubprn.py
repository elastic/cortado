# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="8b5119a5-9f78-492a-8448-ff726b0e0b4f",
    name="execution_pubprn",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="0d4454a7-c682-4085-995c-300973c5bdea", name="Scriptlet Proxy Execution via PubPrn"),
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    siem_rules=[],
    techniques=["T1216", "T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
    RENAMER = _common.get_path("bin", "rcedit-x64.exe")

    cscript = "C:\\Users\\Public\\cscript.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    _common.copy_file(RENAMER, rcedit)
    _common.copy_file(EXE_FILE, cscript)

    cmd = "127.0.0.1 script:https://domain.com/folder/file.sct"
    # Execute command
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute(
        [rcedit, cscript, "--set-version-string", "OriginalFileName", "cscript.exe"],
        timeout=10,
    )
    _common.execute([cscript, "/c", "echo", cmd], timeout=5, kill=True)

    _common.remove_files(cscript, rcedit)
