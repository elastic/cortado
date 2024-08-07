# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="a3461218-f6c2-4178-ad85-f25b8df2d2e1",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Registry Run Key Modified by Unusual Process",
            "rule_id": "b2fcbb09-d9bd-4f6c-a08e-247548b4edcd",
        },
        {
            "rule_name": "Suspicious String Value Written to Registry Run Key",
            "rule_id": "727db78e-e1dd-4bc0-89b0-885cd99e069e",
        },
    ],
    siem_rules=[],
    techniques=["T1547"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    posh = "C:\\Windows\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    cmd = (
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Test -PropertyType String -value rundll32"
    )
    rem_cmd = "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Test"

    # Execute command
    _common.log("Fake ms word reg mod...")
    _common.execute([posh, "/c", cmd], timeout=10)
    _common.execute([posh, "/c", rem_cmd], timeout=10)
    _common.remove_file(posh)


