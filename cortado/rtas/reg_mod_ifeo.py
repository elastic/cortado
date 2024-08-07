# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="2bb1016f-b3e9-455d-b665-02a0aafc797a",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': 'ff5fd85a-e770-4e57-8bae-0d267442eb9f',
        'rule_name': 'Suspicious Image File Execution Options Modification'
    }],
    siem_rules=[],
    techniques=['T1546', 'T1546.012'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    _common.log("Temp Registry mod: IFEO")

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rta.exe\\"
    value = "Debugger"
    data = "Test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
