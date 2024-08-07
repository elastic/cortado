# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Emulate Suspect MS Office Child Processes
# RTA: suspect_office_children.py
# signal.rule.name: Suspicious MS Office Child Process
# ATT&CK: T1064
# Description: Generates network traffic various children processes from emulated Office processes.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="cd8e06c0-fc62-4932-8ef7-b767570e88eb",
    name="suspicious_office_children",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="a624863f-a70d-417f-a7d2-7a404638d47f", name="Suspicious MS Office Child Process"),
        RuleMetadata(id="32f4675e-6c49-4ace-80f9-97c9259dca2e", name="Suspicious MS Outlook Child Process"),
    ],
    techniques=["T1566", "T1566.001"],
)
def main():
    cmd_path = "c:\\windows\\system32\\cmd.exe"
    binaries = ["adobe.exe", "winword.exe", "outlook.exe", "excel.exe", "powerpnt.exe"]
    for binary in binaries:
        _common.copy_file(cmd_path, binary)

    # Execute a handful of commands
    _common.execute(["adobe.exe", "/c", "regsvr32.exe", "/s", "/?"], timeout=5, kill=True)
    _common.execute(["winword.exe", "/c", "certutil.exe"], timeout=5, kill=True)
    _common.execute(["outlook.exe", "/c", "powershell.exe", "-c", "whoami"], timeout=5, kill=True)
    _common.execute(["excel.exe", "/c", "cscript.exe", "-x"], timeout=5, kill=True)

    _common.remove_files(*binaries)
