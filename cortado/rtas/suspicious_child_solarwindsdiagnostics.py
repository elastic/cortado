# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="810554c9-fe55-4fdd-8127-e753ae448d52",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': 'd72e33fc-6e91-42ff-ac8b-e573268c5a87', 'rule_name': 'Command Execution via SolarWinds Process'}],
    techniques=['T1059', 'T1195', 'T1195.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    solarwindsdiagnostics = "C:\\Users\\Public\\solarwindsdiagnostics.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, solarwindsdiagnostics)

    # Execute command
    _common.execute([solarwindsdiagnostics, "/c", powershell], timeout=2, kill=True)
    _common.remove_file(solarwindsdiagnostics)


