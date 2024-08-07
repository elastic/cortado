# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="85cf6796-5f53-4fed-a5cb-8b211882543c",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="0783f666-75ad-4015-9dd5-d39baec8f6b0", name="Potential Credential Access via Rubeus")
    ],
    siem_rules=[],
    techniques=["T1558"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    cmd = "Echo asreproast instead of executing it"
    # Execute command
    _common.execute([powershell, "/c", "echo", cmd], timeout=10)


if __name__ == "__main__":
    exit(main())
