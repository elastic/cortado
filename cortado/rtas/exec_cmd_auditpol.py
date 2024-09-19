# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="92da05da-5acf-473c-809c-6f4cdbced0db",
    name="exec_cmd_auditpol",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="4de76544-f0e5-486a-8f84-eae0b6063cdc",
            name="Disable Windows Event and Security Logs Using Built-in Tools",
        )
    ],
    techniques=["T1070", "T1070.001", "T1562", "T1562.006"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    auditpol = "C:\\Users\\Public\\auditpol.exe"
    _common.copy_file(EXE_FILE, auditpol)

    # Execute command
    _ = _common.execute_command([auditpol, "/c", "echo", "/success:disable"], timeout_secs=10)
    _common.remove_file(auditpol)
