# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="0a9bd666-6dc8-484e-9286-dea82a5661a9",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{"rule_id": "3bc6deaa-fbd4-433a-ae21-3e892f95624f", "rule_name": "NTDS or SAM Database File Copied"}],
    techniques=["T1003", "T1003.002"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _common.execute([powershell, "/c", "echo", "copy", "\\ntds.dit"], timeout=10)


if __name__ == "__main__":
    exit(main())
