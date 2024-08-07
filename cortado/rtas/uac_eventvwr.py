# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="7396debc-65ce-488f-845e-f92e68aceeb1",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="ab29a79a-b3c2-4ae4-9670-70dd0ea68a4a", name="UAC Bypass via Event Viewer"),
    ],
    siem_rules=[],
    techniques=["T1548", "T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    eventvwr = "C:\\Users\\Public\\eventvwr.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, eventvwr)

    _common.execute([eventvwr, "/c", powershell], timeout=2, kill=True)
    _common.remove_files(eventvwr)


