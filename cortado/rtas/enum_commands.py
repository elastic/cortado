# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Common Enumeration Commands
# RTA: enum_commands.py
# ATT&CK: T1007, T1016, T1018, T1035, T1049, T1057, T1063, T1069, T1077, T1082, T1087, T1124, T1135
# Description: Executes a list of administration tools _commonly used by attackers for enumeration.

import argparse
import logging
import random

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9b19f4a3-7287-45d2-ab0f-9a9c0b1bc8e1",
    name="enum_commands",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="7b8bfc26-81d2-435e-965c-d722ee397ef1", name="Windows Network Enumeration"),
        RuleMetadata(id="871ea072-1b71-4def-b016-6278b505138d", name="Enumeration of Administrator Accounts"),
    ],
    techniques=["T1135", "T1069", "T1087", "T1018"],
)
def main(args=None):
    slow_commands = ["gpresult.exe /z", "systeminfo.exe"]

    commands = [
        "ipconfig /all",
        "net localgroup administrators",
        "net user",
        "net user administrator",
        "net user /domain" "tasklist",
        "net view",
        "net view /domain",
        "net view \\\\%s" % _common.get_ip(),
        "netstat -nao",
        "whoami",
        "hostname",
        "net start",
        "tasklist /svc",
        "net time \\\\%s" % _common.get_ip(),
        "net use",
        "net view",
        "net start",
        "net accounts",
        "net localgroup",
        "net group",
        'net group "Domain Admins" /domain',
        "net share",
        "net config workstation",
    ]

    commands.extend(slow_commands)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--sample",
        dest="sample",
        default=len(commands),
        type=int,
        help="Number of commands to run, chosen at random from the list of enumeration commands",
    )
    args = parser.parse_args(args)
    sample = min(len(commands), args.sample)

    if sample < len(commands):
        random.shuffle(commands)

    log.info("Running {} out of {} enumeration commands\n".format(sample, len(commands)))
    for command in commands[0:sample]:
        log.info("About to call {}".format(command))
        if command in slow_commands:
            _ = _common.execute_command(command, kill=True, timeout_secs=15)
            log.info("[output suppressed]", log_type="-")
        else:
            _ = _common.execute_command(command)
