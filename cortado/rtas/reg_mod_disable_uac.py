# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="6a884a9a-b061-4eeb-8711-f14f6b49c9c0",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': 'd31f183a-e5b1-451b-8534-ba62bca0b404',
        'rule_name': 'Disabling User Account Control via Registry Modification'
    }],
    techniques=['T1548', 'T1548.002', 'T1548', 'T1548.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    value = "EnableLUA"
    data = 0

    with _common.temporary_reg(_common.HKLM, key, value, data, data_type="dword"):
        pass


