# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="a840e9b2-5aac-41a1-8c79-03ff624eb77b",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '0022d47d-39c7-4f69-a232-4fe9dc7a3acd', 'rule_name': 'System Shells via Services'}],
    techniques=['T1543', 'T1543.003'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    services = "C:\\Users\\Public\\services.exe"
    pwsh = "C:\\Users\\Public\\pwsh.exe"
    _common.copy_file(EXE_FILE, pwsh)
    _common.copy_file(EXE_FILE, services)

    _common.execute([services, "/c", pwsh], timeout=5, kill=True)
    _common.remove_files(pwsh, services)


if __name__ == "__main__":
    exit(main())
