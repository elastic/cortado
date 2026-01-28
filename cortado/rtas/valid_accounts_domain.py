# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Valid Accounts - Domain Account Usage
# RTA: valid_accounts_domain.py
# ATT&CK: T1078.002
# Description: Simulates domain account enumeration and usage patterns commonly
#              associated with lateral movement and privilege escalation using
#              valid domain credentials.

import logging

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f8a2c3d1-5e6b-4a7f-9c8d-1e2f3a4b5c6d",
    name="valid_accounts_domain",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=["T1078", "T1078.002"],
)
def main():
    """
    Simulates domain account enumeration and usage patterns.

    This RTA executes common domain enumeration commands that attackers use
    after obtaining valid domain credentials. All commands are safe and only
    perform read operations or use echo to simulate suspicious command lines.

    Note: Domain commands may fail on non-domain-joined machines, which is expected.
    We use ignore_failures=True to allow the RTA to continue and generate telemetry.
    """
    log.info("Simulating domain account enumeration and usage patterns")
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Enumerate domain users - common reconnaissance after credential theft
    log.info("Simulating domain user enumeration")
    _ = _common.execute_command(
        ["net.exe", "user", "/domain"],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Enumerate domain groups
    log.info("Simulating domain group enumeration")
    _ = _common.execute_command(
        ["net.exe", "group", "/domain"],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Query domain admins group - high-value target for attackers
    log.info("Simulating Domain Admins group query")
    _ = _common.execute_command(
        ["net.exe", "group", "Domain Admins", "/domain"],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Query enterprise admins group
    log.info("Simulating Enterprise Admins group query")
    _ = _common.execute_command(
        ["net.exe", "group", "Enterprise Admins", "/domain"],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Simulate whoami with domain context - common post-exploitation check
    log.info("Simulating domain context verification")
    _ = _common.execute_command(
        ["whoami.exe", "/all"],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Simulate domain controller query
    log.info("Simulating domain controller enumeration")
    _ = _common.execute_command(
        [powershell, "-Command", "echo", "nltest /dclist:$env:USERDNSDOMAIN"],
        timeout_secs=10,
    )

    # Simulate net use with domain credentials (echo only - safe)
    log.info("Simulating network share access with domain credentials")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'net use \\\\dc01\\c$ /user:DOMAIN\\admin password123'",
        ],
        timeout_secs=10,
    )

    # Simulate WMI query with domain context
    log.info("Simulating WMI query with domain credentials")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'Get-WmiObject -Class Win32_ComputerSystem -ComputerName dc01'",
        ],
        timeout_secs=10,
    )

    log.info("Domain account simulation completed")
