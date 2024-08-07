# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="eb1ecbae-a7d0-4beb-89fe-fbf2db0edce3",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': 'e8571d5f-bea1-46c2-9f56-998de2d3ed95',
        'rule_name': 'Service Control Spawned via Script Interpreter'
    }],
    techniques=['T1021'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    sc = "C:\\Users\\Public\\sc.exe"
    _common.copy_file(EXE_FILE, sc)

    _common.execute([powershell, "/c", sc, "echo", "create"], timeout=5, kill=True)
    _common.remove_files(sc)


