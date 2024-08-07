# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="e9ee4f0c-b8c6-4471-b132-1edf4a7ca441",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c", name="Potential Masquerading as SVCHOST"),
        RuleMetadata(id="eb04896b-935f-4d12-b2ad-579db82e1f42", name="Suspicious Windows Schedule Child Process"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1216", "T1220", "T1053", "T1059"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    svchost = "C:\\Users\\Public\\svchost.exe"
    _common.copy_file(EXE_FILE, svchost)

    _common.execute([svchost, "/c", "echo", "Schedule", "; mshta"], timeout=1, kill=True)
    _common.remove_file(svchost)
