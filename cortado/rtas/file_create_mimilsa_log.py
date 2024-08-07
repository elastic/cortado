# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="4b23eaa2-aa73-43ee-9c10-47ecf01e00aa",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': 'ebb200e8-adf0-43f8-a0bb-4ee5b5d852c6',
        'rule_name': 'Mimikatz Memssp Log File Detected'
    }],
    techniques=['T1003'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    lsass = "C:\\Users\\Public\\lsass.exe"
    fake_log = "C:\\Users\\Public\\mimilsa.log"
    _common.copy_file(EXE_FILE, lsass)

    # Execute command
    _common.execute([lsass, "/c", f"echo AAAAAAAAAAAA | Out-File {fake_log}"], timeout=10)
    _common.remove_files(fake_log, lsass)


