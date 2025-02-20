# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Brute Force Login Attempts
# RTA: brute_force_login.py
# ATT&CK: T1110
# Description: Simulates brute force or password spraying tactics.
#              Remote audit failures must be enabled to trigger: `auditpol /set /subcategory:"Logon" /failure:enable`

import logging
import random
import string
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="35bb73a9-cafa-4b2c-81f0-a97e2afa5e1c",
    name="brute_force_login",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="e08ccd49-0380-4b2b-8d71-8000377d6e49", name="Attempts to Brute Force an Okta User Account")
    ],
    techniques=["T1110"],
)
def main():
    username = "rta-tester"
    remote_host = None

    if not remote_host:
        log.error("A remote host is required to detonate this RTA")
        raise _common.ExecutionError("Remote host is not provided")

    _ = _common.enable_logon_audit(remote_host)

    log.info("Brute forcing login with invalid password against {}".format(remote_host))
    ps_command = """
    $PW = ConvertTo-SecureString "such-secure-passW0RD!" -AsPlainText -Force
    $CREDS = New-Object System.Management.Automation.PsCredential {username}, $PW
    Invoke-WmiMethod -ComputerName {host} -Class Win32_process -Name create -ArgumentList ipconfig -Credential $CREDS
    """
    command = [
        "powershell",
        "-c",
        ps_command.format(username=username, host=remote_host),
    ]

    # fail 4 times
    for _ in range(4):
        _ = _common.execute_command(command, timeout_secs=2)

    time.sleep(1)

    log.info("Password spraying against {}".format(remote_host))

    # fail 5 times
    for _ in range(5):
        random_user = "".join(random.sample(string.ascii_letters, 10))
        command = [
            "powershell",
            "-c",
            ps_command.format(username=random_user, host=remote_host),
        ]
        _ = _common.execute_command(command)

    # allow time for audit event to process
    time.sleep(2)
