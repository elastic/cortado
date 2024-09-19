# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: WMI Incoming Lateral Movement
# RTA: wmi_incoming_logon.py
# ATT&CK: T1047
# Description: Uses PS WMI to trigger 2 logon events via wmi and 1 control logon, which should result in 2 alerts total


import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="3adf005f-94b8-4b34-8994-d5a3dc6666c2",
    name="wmi_incoming_logon",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="f3475224-b179-4f78-8877-c2bd64c26b88", name="WMI Incoming Lateral Movement")],
    techniques=["T1047"],
)
def main():

    remote_host = None

    if not remote_host:
        log.error("A remote host is required to detonate this RTA")
        raise _common.ExecutionError("Remote host is not provided")

    _ = _common.enable_logon_audit(remote_host)

    log.info("Attempting to trigger a remote logon on {}".format(remote_host))

    commands = [
        "Invoke-WmiMethod -ComputerName {} -Class Win32_process -Name create -ArgumentList {}".format(remote_host, c)
        for c in ("ipconfig", "netstat")
    ]

    # trigger twice
    for command in commands:
        _ = _common.execute_command(["powershell", "-c", command])

    # this should not trigger an alert
    _ = _common.execute_command(["net.exe", "time", "\\\\{}".format(remote_host)])
