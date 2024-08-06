# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="92da05da-5acf-473c-809c-6f4cdbced0db",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '4de76544-f0e5-486a-8f84-eae0b6063cdc',
        'rule_name': 'Disable Windows Event and Security Logs Using Built-in Tools'
    }],
    techniques=['T1070', 'T1070.001', 'T1562', 'T1562.006'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    auditpol = "C:\\Users\\Public\\auditpol.exe"
    _common.copy_file(EXE_FILE, auditpol)

    # Execute command
    _common.execute([auditpol, "/c", "echo", "/success:disable"], timeout=10)
    _common.remove_file(auditpol)


if __name__ == "__main__":
    exit(main())
