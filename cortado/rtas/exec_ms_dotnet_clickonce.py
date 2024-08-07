# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="23f0dde3-4803-4976-9a2a-5b5faca50b54",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="8d11d741-7a06-41a1-a525-feaaa07ebbae",
            name="Executable File Creation Followed by Immediate Network Connection",
        ),
        RuleMetadata(id="8606d5fe-5005-4f48-804a-3ad71a22e39d", name="Execution via Microsoft DotNet ClickOnce Host"),
    ],
    siem_rules=[],
    techniques=["T1127", "T1218", "T1036", "T1204", "T1059"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    dfsvc = "C:\\Users\\Public\\dfsvc.exe"
    _common.copy_file(EXE_FILE, dfsvc)
    _common.copy_file(EXE_FILE, rundll32)

    _common.log("Loading mstscax.dll into posh")
    _common.execute([rundll32, "-c", "echo dfshim1ShOpenVerbApplication"], timeout=10)
    _common.execute(
        [
            dfsvc,
            "-c",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "443",
        ],
        timeout=10,
    )
    _common.remove_files(dfsvc, rundll32)
