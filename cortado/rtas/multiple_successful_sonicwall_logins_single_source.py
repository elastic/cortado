# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Multiple Successful SonicWall Logins from a Single Source
# RTA: multiple_successful_sonicwall_logins_single_source.py
# Description: Sends six synthetic SonicWall Enhanced Syslog events representing
#              successful SSL VPN logins by three users from one source IP.
#              The events use the same appliance serial number and source IP so
#              the SonicWall integration normalizes them into one aggregation
#              group that satisfies both thresholds in the detection rule.
#
#              This RTA does not require a SonicWall appliance. It must run on a
#              host where Elastic Agent's SonicWall Firewall integration listens
#              for UDP Enhanced Syslog on the default localhost port 9514.

import logging
import socket
import time
from datetime import UTC, datetime

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 9514

APPLIANCE_IP = "192.0.2.10"
APPLIANCE_SERIAL = "RTA-SONICWALL-001"
SOURCE_IP = "198.51.100.42"
USER_NAMES = ("rta.alice", "rta.bob", "rta.charlie")


def _build_message(username: str, source_port: int, sequence: int) -> bytes:
    """Build an Enhanced Syslog event for SonicWall SSL VPN login success."""
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    message = (
        f'id=firewall sn={APPLIANCE_SERIAL} time="{timestamp}" '
        f"fw={APPLIANCE_IP} pri=6 c=32 gcat=3 m=1080 "
        'msg="SSL VPN zone remote user login allowed" '
        f"n={sequence} src={SOURCE_IP}:{source_port}:X1 "
        f'dst={APPLIANCE_IP}:443:X0 usr="{username}"'
    )
    return message.encode()


@register_code_rta(
    id="409d802e-a873-48d8-b579-8d6430a62fbb",
    name="multiple_successful_sonicwall_logins_single_source",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="7d4a81ea-b9f9-4bf7-8708-5ef7f67e6f3a",
            name="Multiple Successful SonicWall Logins from a Single Source",
        )
    ],
    techniques=["T1110", "T1110.004", "T1078", "T1133"],
)
def main() -> None:
    """Send synthetic SonicWall login-success events to the local Elastic Agent."""
    events = [
        _build_message(username, 55000 + sequence, 900000 + sequence)
        for sequence, username in enumerate(USER_NAMES * 2, start=1)
    ]

    log.info(
        "Sending %d SonicWall Enhanced Syslog events to %s:%d",
        len(events),
        SYSLOG_HOST,
        SYSLOG_PORT,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for event in events:
            _ = sock.sendto(event, (SYSLOG_HOST, SYSLOG_PORT))
            time.sleep(0.1)

    log.info(
        "Sent successful SSL VPN logins for %d users from source %s",
        len(USER_NAMES),
        SOURCE_IP,
    )
