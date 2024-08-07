# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="43331e29-57ba-438f-8d61-99f5d6471aaa",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="92f114fb-7113-4e82-b021-6c2c4ca0a507",
            name="Inhibit System Recovery Followed by a Suspicious File Rename",
        )
    ],
    siem_rules=[],
    techniques=["T1490", "T1486"],
)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    png = "C:\\Windows\\System32\\SecurityAndMaintenance.png"
    tmppng = "C:\\Users\\Public\\SecurityAndMaintenance.png"
    renamed = "C:\\Users\\Public\\renamed.encrypted"
    _common.copy_file(png, tmppng)

    # Execute command
    _common.log("Deleting Shadow Copies using Vssadmin spawned by cmd")
    _common.execute([powershell, "/c", vssadmin, "delete", "shadows", "/For=C:"], timeout=10)

    _common.log("Renaming image to unknown extension")
    _common.execute([powershell, "/c", f"Rename-Item {tmppng} {renamed}"], timeout=10)

    _common.remove_file(renamed)
