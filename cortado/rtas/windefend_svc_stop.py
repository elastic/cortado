# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="811ccfc2-d0fc-4a2a-85f6-6dc1235278bf",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="32ab2977-2932-4172-9117-36e382591818", name="Attempt to Disable Windows Defender Services"),
    ],
    siem_rules=[],
    techniques=["T1562", "T1036"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    tempshell = "C:\\Users\\Public\\powershell.exe"
    _common.copy_file(powershell, tempshell)

    # Execute command
    _common.log("Attempting to stop Windefend, which will not work unless running as SYSTEM")
    _common.execute([tempshell, "/c", "sc.exe stop Windefend"])
    _common.remove_file(tempshell)
