# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="b6b65c6a-830a-4e1c-ace7-3c98362f998b",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '6aace640-e631-4870-ba8e-5fdda09325db',
        'rule_name': 'Exporting Exchange Mailbox via PowerShell'
    }],
    techniques=['T1005', 'T1114', 'T1114.002'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _common.execute([powershell, "/c", "echo", "New-MailboxExportRequest"], timeout=10)


if __name__ == "__main__":
    exit(main())
