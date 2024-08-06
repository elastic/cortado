# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="0c0febf3-1ac3-4198-a31a-ec80b1f5ebbe",
    platforms=["windows"],
    endpoint_rules=[
        {"rule_id": "5abd98fb-ffbe-4cd6-9592-3cda7b155ff5", "rule_name": "Ingress Tool Transfer via PowerShell"},
        {"rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f", "rule_name": "Binary Masquerading via Untrusted Path"},
    ],
    siem_rules=[],
    techniques=['T1105', 'T1059', 'T1059.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Users\\Public\\powershell.exe"
    _common.copy_file(EXE_FILE, powershell)

    _common.execute([powershell, "echo http;", powershell], timeout=5, kill=True)
    _common.remove_files(powershell)


if __name__ == "__main__":
    exit(main())
