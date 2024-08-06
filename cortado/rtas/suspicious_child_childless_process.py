# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="b63e7b4a-85a6-4b4f-bf72-abe49d04b24f",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '6a8ab9cc-4023-4d17-b5df-1a3e16882ce7',
        'rule_name': 'Unusual Service Host Child Process - Childless Service'
    }],
    techniques=['T1055', 'T1055.012', 'T1055'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    svchost = "C:\\Users\\Public\\svchost.exe"
    rta = "C:\\Users\\Public\\rta.exe"
    _common.copy_file(EXE_FILE, rta)
    _common.copy_file(EXE_FILE, svchost)

    _common.execute([svchost, "echo", "WdiSystemHost", ";", rta], timeout=5, kill=True)
    _common.remove_files(rta, svchost)


if __name__ == "__main__":
    exit(main())
