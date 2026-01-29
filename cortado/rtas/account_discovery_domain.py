# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Domain Account Discovery
# RTA: account_discovery_domain.py
# ATT&CK: T1087, T1087.002
# Description: Simulates domain account discovery techniques commonly used by
#              attackers during reconnaissance to enumerate domain users, groups,
#              and privileged accounts.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d1d2d3d4-e5e6-f7f8-a9a0-b1b2b3b4b5b6",
    name="account_discovery_domain",
    platforms=[OSType.WINDOWS, OSType.LINUX],
    endpoint_rules=[
        # Endpoint rule: Domain Accounts Enumeration via LDAP Search
        RuleMetadata(
            id="c3b3cd2e-04f5-457f-8d69-f92468f22eae",
            name="Domain Accounts Enumeration via LDAP Search",
        ),
        # Endpoint rule: Group and Privileged Accounts Discovery via LDAP
        RuleMetadata(
            id="447b004a-ac74-4ba4-8131-44efc25fdd47",
            name="Group and Privileged Accounts Discovery via LDAP",
        ),
        RuleMetadata(
            id="65784f6e-247a-466b-bbfb-cd92024f7e82",
            name="Suspicious PowerShell Execution",
        ),
    ],
    siem_rules=[
        # SIEM rule: Enumeration of Administrator Accounts
        RuleMetadata(
            id="871ea072-1b71-4def-b016-6278b505138d",
            name="Enumeration of Administrator Accounts",
        ),
    ],
    techniques=["T1087", "T1087.002"],
)
def main():
    """
    Simulates domain account discovery using built-in tools.

    This RTA demonstrates reconnaissance patterns used to enumerate domain
    users, groups, and service accounts after gaining initial access.
    Detects the current OS and runs the appropriate simulation.
    """
    current_os = _common.get_current_os()

    if current_os == OSType.WINDOWS:
        _run_windows()
    elif current_os == OSType.LINUX:
        _run_linux()
    else:
        log.warning(f"Unsupported OS: {current_os}")


def _run_windows():
    """Windows-specific domain account discovery simulation."""
    log.info("Simulating Windows domain account discovery techniques")
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Note: Domain commands may fail on non-domain-joined machines, which is expected.
    # We use ignore_failures=True to allow the RTA to continue and generate telemetry.

    # Enumerate all domain users
    log.info("Enumerating domain users via net.exe")
    _ = _common.execute_command(
        ["net.exe", "user", "/domain"],
        timeout_secs=15,
        ignore_failures=True,
    )

    # Enumerate domain groups
    log.info("Enumerating domain groups via net.exe")
    _ = _common.execute_command(
        ["net.exe", "group", "/domain"],
        timeout_secs=15,
        ignore_failures=True,
    )

    # Query Domain Admins group membership
    log.info("Querying Domain Admins group membership")
    _ = _common.execute_command(
        ["net.exe", "group", "Domain Admins", "/domain"],
        timeout_secs=15,
        ignore_failures=True,
    )

    # Query Enterprise Admins group membership
    log.info("Querying Enterprise Admins group membership")
    _ = _common.execute_command(
        ["net.exe", "group", "Enterprise Admins", "/domain"],
        timeout_secs=15,
        ignore_failures=True,
    )

    # Query Schema Admins group membership
    log.info("Querying Schema Admins group membership")
    _ = _common.execute_command(
        ["net.exe", "group", "Schema Admins", "/domain"],
        timeout_secs=15,
        ignore_failures=True,
    )

    # Query Account Operators group
    log.info("Querying Account Operators group")
    _ = _common.execute_command(
        ["net.exe", "group", "Account Operators", "/domain"],
        timeout_secs=15,
        ignore_failures=True,
    )

    # Simulate LDAP query for domain users via PowerShell
    log.info("Simulating LDAP domain user query")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'([ADSISearcher]\"(&(objectCategory=person)(objectClass=user))\").FindAll()'",
        ],
        timeout_secs=10,
    )

    # Simulate service account enumeration
    log.info("Simulating service account enumeration")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"} -Properties ServicePrincipalName'",
        ],
        timeout_secs=10,
    )

    # Query domain computers
    log.info("Querying domain computers")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'Get-ADComputer -Filter * -Properties DNSHostName'",
        ],
        timeout_secs=10,
    )

    # Simulate dsquery for domain users
    log.info("Simulating dsquery domain user enumeration")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'dsquery user -limit 0'",
        ],
        timeout_secs=10,
    )

    # Simulate wmic useraccount enumeration
    log.info("Simulating wmic domain account enumeration")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'wmic useraccount list /format:csv'",
        ],
        timeout_secs=10,
    )

    # Simulate net localgroup administrators query
    log.info("Querying local administrators group")
    _ = _common.execute_command(
        ["net.exe", "localgroup", "Administrators"],
        timeout_secs=10,
        ignore_failures=True,
    )

    log.info("Windows domain account discovery simulation completed")


def _run_linux():
    """Linux-specific domain account discovery via LDAP simulation."""
    log.info("Simulating Linux domain account discovery via LDAP")

    # Create masquerade binary
    masquerade = "/tmp/ldapsearch"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Simulate ldapsearch for domain users
    log.info("Simulating ldapsearch domain user enumeration")
    _ = _common.execute_command(
        [
            masquerade,
            "-x",
            "-H",
            "ldap://dc.domain.local",
            "-b",
            "dc=domain,dc=local",
            "(objectClass=user)",
        ],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Simulate ldapsearch for domain groups
    log.info("Simulating ldapsearch domain group enumeration")
    _ = _common.execute_command(
        [
            masquerade,
            "-x",
            "-H",
            "ldap://dc.domain.local",
            "-b",
            "dc=domain,dc=local",
            "(objectClass=group)",
        ],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Simulate ldapsearch for admin accounts
    log.info("Simulating ldapsearch admin enumeration")
    _ = _common.execute_command(
        [
            masquerade,
            "-x",
            "-b",
            "CN=Domain Admins,CN=Users,DC=domain,DC=local",
        ],
        timeout_secs=10,
        ignore_failures=True,
    )

    # Cleanup
    log.info("Cleaning up simulation files")
    _common.remove_file(masquerade)

    log.info("Linux domain account discovery simulation completed")
