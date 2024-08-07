# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="2e2b5db2-2edb-421e-bb5e-6d2ab09303e0",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="e3343ab9-4245-4715-b344-e11c56b0a47f", name="Process Activity via Compiled HTML File")
    ],
    techniques=["T1204", "T1204.002", "T1218", "T1218.001"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    hh = "C:\\Users\\Public\\hh.exe"
    mshta = "C:\\Windows\\System32\\mshta.exe"
    _common.copy_file(EXE_FILE, hh)

    # Execute command
    _common.execute([hh, "/c", mshta], timeout=2, kill=True)
    _common.remove_file(hh)
