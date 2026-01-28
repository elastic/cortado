# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Clear Linux System Logs
# RTA: clear_linux_system_logs.py
# ATT&CK: T1070, T1070.002, T1070.003
# Description: Simulates clearing of Linux system logs and shell history to cover
#              tracks, a common technique used by attackers after compromise.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b1b2b3b4-c5c6-d7d8-e9e0-f1f2f3f4f5f6",
    name="clear_linux_system_logs",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="c1b2b3b4-c5c6-d7d8-e9e0-f1f2f3f4f5f7",
            name="Linux System Log Cleared",
        ),
        RuleMetadata(
            id="d1b2b3b4-c5c6-d7d8-e9e0-f1f2f3f4f5f8",
            name="Potential Log Tampering via File Truncation",
        ),
        RuleMetadata(
            id="e1b2b3b4-c5c6-d7d8-e9e0-f1f2f3f4f5f9",
            name="Suspicious Log File Deletion",
        ),
        RuleMetadata(
            id="c2b3b4b5-c6c7-d8d9-e0e1-f2f3f4f5f6f8",
            name="Linux Command History Cleared",
        ),
    ],
    siem_rules=[
        RuleMetadata(
            id="f1b2b3b4-c5c6-d7d8-e9e0-f1f2f3f4f5fa",
            name="Linux Log Files Cleared",
        ),
        RuleMetadata(
            id="d2b3b4b5-c6c7-d8d9-e0e1-f2f3f4f5f6f9",
            name="Linux Shell History File Modification",
        ),
    ],
    techniques=["T1070", "T1070.002", "T1070.003"],
)
def main():
    """
    Simulates clearing of Linux system logs and shell history.

    This RTA demonstrates log clearing techniques used by attackers to remove
    evidence of their activities. All operations target temporary test files
    or use echo commands to simulate the behavior.
    """
    log.info("Simulating Linux system log and history clearing techniques")

    # Create masquerade binaries
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")

    masquerade_rm = "/tmp/rm"
    masquerade_truncate = "/tmp/truncate"
    masquerade_cat = "/tmp/cat"
    masquerade_shred = "/tmp/shred"
    masquerade_echo = "/tmp/echo"
    masquerade_bash = "/tmp/bash"

    for masq in [masquerade_rm, masquerade_truncate, masquerade_cat, masquerade_shred, masquerade_echo, masquerade_bash]:
        _common.copy_file(source, masq)
        _ = _common.execute_command(["chmod", "+x", masq])

    # ============================================
    # System Log Clearing (T1070.002)
    # ============================================

    # Simulate clearing /var/log/auth.log
    log.info("Simulating auth.log clearing")
    _ = _common.execute_command(
        [masquerade_cat, "/dev/null", ">", "/var/log/auth.log"],
        timeout_secs=10,
    )

    # Simulate clearing /var/log/syslog
    log.info("Simulating syslog clearing")
    _ = _common.execute_command(
        [masquerade_truncate, "-s", "0", "/var/log/syslog"],
        timeout_secs=10,
    )

    # Simulate clearing /var/log/messages
    log.info("Simulating messages log clearing")
    _ = _common.execute_command(
        [masquerade_echo, "", ">", "/var/log/messages"],
        timeout_secs=10,
    )

    # Simulate clearing /var/log/secure (RHEL/CentOS)
    log.info("Simulating secure log clearing")
    _ = _common.execute_command(
        [masquerade_truncate, "-s", "0", "/var/log/secure"],
        timeout_secs=10,
    )

    # Simulate clearing wtmp (login records)
    log.info("Simulating wtmp clearing")
    _ = _common.execute_command(
        [masquerade_cat, "/dev/null", ">", "/var/log/wtmp"],
        timeout_secs=10,
    )

    # Simulate clearing btmp (failed login attempts)
    log.info("Simulating btmp clearing")
    _ = _common.execute_command(
        [masquerade_truncate, "-s", "0", "/var/log/btmp"],
        timeout_secs=10,
    )

    # Simulate clearing lastlog
    log.info("Simulating lastlog clearing")
    _ = _common.execute_command(
        [masquerade_cat, "/dev/null", ">", "/var/log/lastlog"],
        timeout_secs=10,
    )

    # Simulate rm -rf /var/log/*
    log.info("Simulating recursive log deletion")
    _ = _common.execute_command(
        [masquerade_rm, "-rf", "/var/log/*.log"],
        timeout_secs=10,
    )

    # Simulate shred of log files (secure deletion)
    log.info("Simulating secure log file deletion via shred")
    _ = _common.execute_command(
        [masquerade_shred, "-u", "-z", "/var/log/auth.log"],
        timeout_secs=10,
    )

    # Simulate journalctl log clearing
    log.info("Simulating journalctl log vacuum")
    masquerade_journalctl = "/tmp/journalctl"
    _common.copy_file(source, masquerade_journalctl)
    _ = _common.execute_command(["chmod", "+x", masquerade_journalctl])
    _ = _common.execute_command(
        [masquerade_journalctl, "--vacuum-time=1s"],
        timeout_secs=10,
    )

    # Simulate clearing audit logs
    log.info("Simulating audit log clearing")
    _ = _common.execute_command(
        [masquerade_truncate, "-s", "0", "/var/log/audit/audit.log"],
        timeout_secs=10,
    )

    # ============================================
    # Shell History Clearing (T1070.003)
    # ============================================

    # Simulate history -c command
    log.info("Simulating history -c command")
    _ = _common.execute_command(
        [masquerade_bash, "-c", "history -c"],
        timeout_secs=10,
    )

    # Simulate clearing .bash_history
    log.info("Simulating .bash_history truncation")
    _ = _common.execute_command(
        [masquerade_cat, "/dev/null", ">", "~/.bash_history"],
        timeout_secs=10,
    )

    # Simulate clearing .zsh_history
    log.info("Simulating .zsh_history clearing")
    _ = _common.execute_command(
        [masquerade_rm, "-f", "~/.zsh_history"],
        timeout_secs=10,
    )

    # Simulate HISTFILE unset
    log.info("Simulating HISTFILE unset")
    _ = _common.execute_command(
        [masquerade_bash, "-c", "unset HISTFILE"],
        timeout_secs=10,
    )

    # Simulate HISTSIZE=0
    log.info("Simulating HISTSIZE=0")
    _ = _common.execute_command(
        [masquerade_bash, "-c", "export HISTSIZE=0"],
        timeout_secs=10,
    )

    # Create a temporary log file and delete it to trigger detection
    log.info("Creating and deleting temporary log file")
    temp_log = Path("/tmp/test_system.log")
    _common.create_file_with_data(
        str(temp_log),
        "Test log entry for RTA simulation\n",
    )
    _common.remove_file(str(temp_log))

    # Cleanup masquerade binaries
    log.info("Cleaning up simulation files")
    for masq in [masquerade_rm, masquerade_truncate, masquerade_cat, masquerade_shred, masquerade_echo, masquerade_bash, masquerade_journalctl]:
        _common.remove_file(masq)

    log.info("Linux system log and history clearing simulation completed")
