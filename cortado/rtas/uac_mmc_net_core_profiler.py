# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="33f20563-7d1b-46a4-8644-a563f2488120",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        {
            "rule_name": "UAC Bypass Attempt via MMC DLL Search Order Hijacking",
            "rule_id": "28996098-b9be-4aa8-a1f3-4923c84b2649",
        },
    ],
    siem_rules=[],
    techniques=["T1574", "T1548", "T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    key = "Environment"
    value = "COR_PROFILER_PATH"
    data = "temp.dll"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass

    mmc = "C:\\Users\\Public\\mmc.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, mmc)

    _common.execute([mmc, "/c", powershell], timeout=2, kill=True)
    _common.remove_files(mmc)


if __name__ == "__main__":
    exit(main())
