# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="b30811a1-f734-4c28-b386-bcf43b214e09",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="17030515-5ed0-43c8-9602-f97cbebd43c0", name="Execution via Outlook Application COM Object"),
        RuleMetadata(id="5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c", name="Potential Masquerading as SVCHOST"),
    ],
    siem_rules=[],
    techniques=["T1566", "T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    outlook = "C:\\Users\\Public\\outlook.exe"
    svchost = "C:\\Users\\Public\\svchost.exe"
    _common.copy_file(EXE_FILE, outlook)
    _common.copy_file(EXE_FILE, svchost)

    _common.log("Fake outlook spawning powershell")
    _common.execute([svchost, "/c", outlook, "/c", "powershell -Embedding"], timeout=10, kill=True)

    _common.remove_files(outlook, svchost)
