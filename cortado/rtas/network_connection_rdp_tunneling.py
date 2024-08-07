# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="7143aab0-c4f3-43da-a11e-aca589887860",
    name="network_connection_rdp_tunneling",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="76fd43b7-3480-4dd9-8ad7-8bd36bfad92f", name="Potential Remote Desktop Tunneling Detected")
    ],
    techniques=["T1572"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _common.execute([powershell, "/c", "echo", "127.0.0.1:3389", "-ssh"], timeout=10)
