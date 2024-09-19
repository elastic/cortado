# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Lateral Movement Commands
# RTA: lateral_commands.py
# Elatic Detection: Local Service Commands
# signal.rule.name: Local Scheduled Task Commands
# signal.rule.name: Whoami Process Activity
# ATT&CK: T1021, T1047, T1077, T1124, T1126
# Description: Runs various Windows commands typically used by attackers to move laterally from the local machine.

import logging
import os
import re

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


MY_APP_EXE = "bin/myapp.exe"


@register_code_rta(
    id="389392dc-61db-4e45-846f-099f7d289c1b",
    name="lateral_commands",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="d61cbcf8-1bc1-4cff-85ba-e7b21c5beedc", name="Service Command Lateral Movement")],
    techniques=["T1569", "T1021", "T1543"],
    ancillary_files=[MY_APP_EXE],
)
def main():
    remote_host = _common.get_host_ip()
    log.info("Attempting to laterally move to %s" % remote_host)

    remote_host = _common.resolve_hostname(remote_host)
    log.info("Using ip address %s" % remote_host)

    # Put the hostname in quotes for WMIC, but leave it as is
    if not re.match(_const.IP_REGEX, remote_host):
        wmi_node = f'"{remote_host}"'
    else:
        wmi_node = remote_host

    commands = [
        "sc.exe \\\\{host} create test_service binPath= %s" % MY_APP_EXE,
        "sc.exe \\\\{host} config test_service binPath= c:\\windows\\system32\\ipconfig.exe",
        "sc.exe \\\\{host} failure test_service command= c:\\windows\\system32\\net.exe",
        "sc.exe \\\\{host} start test_service",
        "sc.exe \\\\{host} delete test_service",
        "wmic.exe /node:{wmi_node} process call create ipconfig.exe",
        "wmic.exe /node:{wmi_node} path WIN32_USERACCOUNT where(name='vagrant') set passwordexpires='false'",
        "net.exe time \\\\{host}",
        "net.exe use \\\\{host}\\admin$",
        "net.exe use \\\\{host}\\admin$ /delete",
        "net.exe use \\\\{host}\\c$",
        "net.exe use \\\\{host}\\c$ /delete",
    ]

    for command in commands:
        formatted_command = command.format(host=remote_host, wmi_node=wmi_node)
        _ = _common.execute_command([formatted_command])

    _, whoami, _ = _common.execute_command(["whoami"])
    _, hostname, _ = _common.execute_command(["hostname"])

    if not whoami or not hostname:
        raise _common.ExecutionError("Can't get `whoami` or `hostname` command results")

    whoami = whoami.lower()

    separator = "\\\\"
    domain, _, _ = whoami.partition(separator)
    hostname = hostname.lower()
    schtasks_host = remote_host

    # Check if the account is local or a domain
    if domain in (hostname, "NT AUTHORITY"):
        log.info("Need password for remote scheduled task in workgroup. Performing instead on %s." % _common.get_host_ip())
        schtasks_host = _common.get_host_ip()

    task_name = "test_task-%d" % os.getpid()
    schtask_commands = [
        r"schtasks /s {host} /delete /tn {name} /f",
        r"schtasks /s {host} /create /SC MONTHLY /MO first /D SUN /tn {name} /tr c:\windows\system32\ipconfig.exe /f",
        r"schtasks /s {host} /run /tn {name}",
        r"schtasks /s {host} /delete /tn {name} /f",
    ]

    for command in schtask_commands:
        command = command.format(host=schtasks_host, name=task_name)
        _ = _common.execute_command(command)

    # Remote powershell
    _ = _common.execute_command(["C:\\Windows\\system32\\wsmprovhost.exe", "-Embedding"], timeout_secs=5)
