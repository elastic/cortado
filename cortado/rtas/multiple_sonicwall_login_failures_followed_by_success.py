# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Multiple SonicWall Login Failures Followed by Successful Login
# RTA: multiple_sonicwall_login_failures_followed_by_success.py
# Description: Sends five synthetic SonicWall Enhanced Syslog login failures
#              affecting three users, followed by one successful SSL VPN login.
#              Every event uses the same source IP and appliance serial number
#              so the integration produces one ES|QL aggregation group.
#
#              This RTA does not require a SonicWall appliance. It must run on a
#              host where Elastic Agent's SonicWall Firewall integration listens
#              for UDP Enhanced Syslog on the default localhost port 9514.

import logging
import socket
import time
from datetime import UTC, datetime, timedelta

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 9514

APPLIANCE_IP = "192.0.2.10"
APPLIANCE_SERIAL = "RTA-SONICWALL-002"
SOURCE_IP = "198.51.100.43"
FAILED_USER_NAMES = (
    "rta.alice",
    "rta.bob",
    "rta.charlie",
    "rta.alice",
    "rta.bob",
)
SUCCESSFUL_USER_NAME = "rta.alice"


def _build_failure_message(
    username: str,
    source_port: int,
    sequence: int,
    timestamp: datetime,
) -> bytes:
    """Build an Enhanced Syslog LDAP invalid-credential event."""
    event_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    message = (
        f'id=firewall sn={APPLIANCE_SERIAL} time="{event_time}" '
        f"fw={APPLIANCE_IP} pri=5 c=16 gcat=3 m=749 "
        'msg="User login denied - invalid credentials on LDAP server" '
        f"n={sequence} src={SOURCE_IP}:{source_port}:X1 "
        f'dst={APPLIANCE_IP}:443:X0 usr="{username}"'
    )
    return message.encode()


def _build_success_message(
    username: str,
    source_port: int,
    sequence: int,
    timestamp: datetime,
) -> bytes:
    """Build an Enhanced Syslog SSL VPN login-success event."""
    event_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    message = (
        f'id=firewall sn={APPLIANCE_SERIAL} time="{event_time}" '
        f"fw={APPLIANCE_IP} pri=6 c=32 gcat=3 m=1080 "
        'msg="SSL VPN zone remote user login allowed" '
        f"n={sequence} src={SOURCE_IP}:{source_port}:X1 "
        f'dst={APPLIANCE_IP}:443:X0 usr="{username}"'
    )
    return message.encode()


@register_code_rta(
    id="b747d8e3-2f7a-4f0c-9d6f-2baf8fc36211",
    name="multiple_sonicwall_login_failures_followed_by_success",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="efe7ac71-3b13-41cf-8263-30af68ce3f19",
            name="Multiple SonicWall Login Failures Followed by Successful Login",
        )
    ],
    techniques=["T1110", "T1110.001", "T1110.003", "T1110.004", "T1078", "T1133"],
)
def main() -> None:
    """Send SonicWall login failures followed by one successful login."""
    base_time = datetime.now(UTC) - timedelta(seconds=10)
    failures = [
        _build_failure_message(
            username,
            55000 + index,
            910000 + index,
            base_time + timedelta(seconds=index - 1),
        )
        for index, username in enumerate(FAILED_USER_NAMES, start=1)
    ]
    success = _build_success_message(
        SUCCESSFUL_USER_NAME,
        55006,
        910006,
        base_time + timedelta(seconds=8),
    )

    log.info(
        "Sending %d SonicWall login failures followed by one success to %s:%d",
        len(failures),
        SYSLOG_HOST,
        SYSLOG_PORT,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for event in failures:
            _ = sock.sendto(event, (SYSLOG_HOST, SYSLOG_PORT))
            time.sleep(0.1)
        _ = sock.sendto(success, (SYSLOG_HOST, SYSLOG_PORT))

    log.info(
        "Sent failures for %d users and a successful login from source %s",
        len(set(FAILED_USER_NAMES)),
        SOURCE_IP,
    )
