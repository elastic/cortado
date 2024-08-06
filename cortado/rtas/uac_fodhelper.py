# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="a67586fd-cceb-4fb9-bf0e-d355b9e8921a",
    platforms=["windows"],
    endpoint_rules=[
        {"rule_name": "UAC Bypass via FodHelper Execution Hijack", "rule_id": "b5c0058e-2bca-4ed5-84b3-4e017c039c57"}
    ],
    siem_rules=[],
    techniques=["T1548"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    key = "Software\\Classes\\ms-settings\\shell\\open\\command"
    value = "test"
    data = "test"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass

    fodhelper = "C:\\Users\\Public\\fodhelper.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, fodhelper)

    _common.execute([fodhelper, "/c", powershell], timeout=2, kill=True)
    _common.remove_file(fodhelper)


if __name__ == "__main__":
    exit(main())
