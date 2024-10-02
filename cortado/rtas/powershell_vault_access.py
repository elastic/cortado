# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="88905741-350f-4a20-a363-22be1e71840c",
    name="powershell_vault_access",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7a4d1be2-db47-4545-a08c-9d4b20bad0d0", name="Access to Windows Passwords Vault via Powershell")
    ],
    techniques=["T1555", "T1059"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    cmd = "(new-object 'Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials"
    "ContentType=WindowsRuntime').RetrieveAll()"

    # Execute command
    _ = _common.execute_command([powershell, "/c", cmd], timeout_secs=5)
