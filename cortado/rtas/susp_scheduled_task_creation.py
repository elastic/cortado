# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="0a766d3c-baee-4bc2-8997-e4e450f77253",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="5db08297-bf72-49f4-b426-f405c2b01326", name="Regsvr32 with Unusual Arguments"),
        RuleMetadata(id="beebd95c-93f4-46d2-a902-053bfe78686b", name="Suspicious Scheduled Task Creation"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1053", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    regsvr32 = "C:\\Users\\Public\\regsvr32.exe"
    _common.copy_file(EXE_FILE, regsvr32)

    cmd = "schtasks.exe /create /tr C:\\Users\\Public\\ /mo minute"
    # Execute command
    _common.execute([regsvr32, "/c", cmd], timeout=10)
    _common.remove_file(regsvr32)
