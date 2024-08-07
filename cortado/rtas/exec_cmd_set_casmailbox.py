# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="0eb19c28-f82f-4f69-b11f-3b946f310e32",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': 'ce64d965-6cb0-466d-b74f-8d2c76f47f05',
        'rule_name': 'New ActiveSyncAllowedDeviceID Added via PowerShell'
    }],
    techniques=['T1098', 'T1098.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.execute([powershell, "/c", "echo", "Set-CASMailbox ActiveSyncAllowedDeviceIDs"], timeout=5, kill=True)


if __name__ == "__main__":
    exit(main())
