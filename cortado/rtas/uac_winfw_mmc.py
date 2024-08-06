# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="2f19d0f2-64cb-41db-81e6-da06f9e83bcb",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="18a26e3e-e535-4d23-8ffa-a3cdba56d16e", name="Suspicious Parent-Child Relationship"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        {
            "rule_name": "UAC Bypass via Windows Firewall Snap-In Hijack",
            "rule_id": "65f52068-4d08-41af-9fd7-0c1a4f732494",
        },
    ],
    siem_rules=[],
    techniques=["T1574", "T1055", "T1548", "T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    mmc = "C:\\Users\\Public\\mmc.exe"
    dllhost = "C:\\Users\\Public\\dllhost.exe"
    dccwpathdll = "C:\\Windows\\assembly\\temp\\a.dll"
    dccwpathdll2 = "C:\\Windows\\assembly\\temp\\Accessibility.ni.dll"
    _common.copy_file(EXE_FILE, mmc)
    _common.copy_file(EXE_FILE, dllhost)

    _common.copy_file(EXE_FILE, dccwpathdll)
    _common.execute([dllhost, "/c", f"Rename-Item {dccwpathdll} {dccwpathdll2}"], timeout=10)
    _common.execute([mmc, "/c", "echo", "WF.msc", ";powershell"], timeout=2, kill=True)
    _common.remove_files(mmc, dllhost, dccwpathdll2)


if __name__ == "__main__":
    exit(main())
