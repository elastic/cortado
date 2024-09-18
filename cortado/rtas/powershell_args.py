# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Powershell with Suspicious Arguments
# RTA: powershell_args.py
# ATT&CK: T1140
# Description: Calls PowerShell with suspicious command line arguments.

import base64
import logging
from pathlib import Path

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="5efc844c-0c11-4f84-a904-ada611315298",
    name="powershell_args",
    platforms=[OSType.WINDOWS],
)
def encode(command):
    return base64.b64encode(command.encode("utf-16le"))


def main():
    log.info("PowerShell Suspicious Commands")
    temp_script = Path("tmp.ps1").resolve()

    # Create an empty script
    with open(temp_script, "w") as f:
        f.write("whoami.exe\nexit\n")

    powershell_commands = [
        ["powershell.exe", "-ExecutionPol", "Bypass", temp_script],
        ["powershell.exe", "iex", "Get-Process"],
        ["powershell.exe", "-ec", encode("Get-Process" + " " * 1000)],
    ]

    for command in powershell_commands:
        _ = _common.execute_command(command)

    _common.remove_file(temp_script)
