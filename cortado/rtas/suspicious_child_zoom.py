# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="00402735-f78d-4ed6-9f8e-a1b365c42f5b",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '97aba1ef-6034-4bd3-8c1a-1e0996b27afa', 'rule_name': 'Suspicious Zoom Child Process'}],
    techniques=['T1036', 'T1055'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    zoom = "C:\\Users\\Public\\zoom.exe"
    pwsh = "C:\\Users\\Public\\pwsh.exe"
    _common.copy_file(EXE_FILE, zoom)
    _common.copy_file(EXE_FILE, pwsh)

    # Execute command
    _common.execute([zoom, "/c", pwsh], timeout=2, kill=True)
    _common.remove_files(zoom, pwsh)


