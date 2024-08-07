# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="f8ffc63a-4a54-44a8-ac55-9c63e1bb584c",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Suspicious Credential Files Creation via Kerberos",
            "rule_id": "ced93ac0-f153-402f-9239-17ae32f304e2",
        }
    ],
    siem_rules=[],
    techniques=["T1558", "T1021"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    cmd1 = "Test-NetConnection -ComputerName portquiz.net -Port 445"
    cmd2 = "echo 'aaa' > a.kirbi; rm a.kirbi"
    # Execute command
    _common.log("Connecting to port 88 and creating a empty .kirbi file")
    _common.execute([powershell, "/c", cmd1, ";", cmd2], timeout=10)


if __name__ == "__main__":
    exit(main())
