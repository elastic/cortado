# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="c9b68802-7d8b-4806-a817-ad50032efc58",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="9d1d6c77-8acc-478b-8a1f-43da8fa151c7", name="Suspicious Execution via MSIEXEC"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    msiexec = "C:\\Users\\Public\\msiexec.exe"
    _common.copy_file(EXE_FILE, msiexec)

    # Execute command
    _common.execute([powershell, "/c", msiexec], timeout=10, kill=True)
    _common.remove_file(msiexec)


if __name__ == "__main__":
    exit(main())
