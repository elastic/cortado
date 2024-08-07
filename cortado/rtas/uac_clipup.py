# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="1d887a40-ea2a-493c-90b4-54e0ce4f3534",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': 'b90cdde7-7e0d-4359-8bf0-2c112ce2008a',
        'rule_name': 'UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface'
    }],
    techniques=['T1548', 'T1548.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    dllhost = "C:\\Users\\Public\\dllhost.exe"
    clipup = "C:\\Users\\Public\\clipup.exe"
    _common.copy_file(EXE_FILE, clipup)
    _common.copy_file(EXE_FILE, dllhost)

    _common.execute([dllhost, "echo", "/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}",
                   ";", clipup], timeout=5, kill=True)
    _common.remove_files(clipup, dllhost)


