# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="d62cd5fb-0e8f-4f20-9477-b8622772ed16",
    name="suspicious_child_acrobat",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="53a26770-9cbd-40c5-8b57-61d01a325e14", name="Suspicious PDF Reader Child Process")],
    techniques=["T1204"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    acrobat = "C:\\Users\\Public\\Acrobat.exe"
    arp = "C:\\Windows\\System32\\arp.exe"
    _common.copy_file(EXE_FILE, acrobat)

    # Execute command
    _common.execute([acrobat, "/c", arp], timeout=2, kill=True)
    _common.remove_file(acrobat)
