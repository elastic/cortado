# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="b434626c-4787-4967-9984-50c0db12692f",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': 'd0e159cf-73e9-40d1-a9ed-077e3158a855', 'rule_name': 'Registry Persistence via AppInit DLL'}],
    techniques=['T1546', 'T1546.010'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    value = "AppInit_Dlls"
    data = "RTA"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


