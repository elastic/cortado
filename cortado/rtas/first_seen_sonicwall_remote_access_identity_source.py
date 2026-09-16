# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Seen SonicWall Remote Access Login by User and Source
# RTA: first_seen_sonicwall_remote_access_identity_source.py
# Description: Sends one synthetic SonicWall Enhanced Syslog SSL VPN login
#              success (event 1080). The appliance serial and user name are
#              stable identifiers; the source IP is randomized on each run so
#              the new-terms key (serial, user, source IP) is unseen in the
#              rule's 14-day history window.
#
#              This RTA does not require a SonicWall appliance. It must run on a
#              host where Elastic Agent's SonicWall Firewall integration listens
#              for UDP Enhanced Syslog on the default localhost port 9514.

import logging
import random
import socket
from datetime import UTC, datetime

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 9514

APPLIANCE_IP = "192.0.2.10"
APPLIANCE_SERIAL = "RTA-SONICWALL-003"
USER_NAME = "rta.remote"


def _build_success_message(source_ip: str, source_port: int, sequence: int) -> bytes:
    """Build an Enhanced Syslog SSL VPN login-success event."""
    event_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    message = (
        f'id=firewall sn={APPLIANCE_SERIAL} time="{event_time}" '
        f"fw={APPLIANCE_IP} pri=6 c=32 gcat=3 m=1080 "
        'msg="SSL VPN zone remote user login allowed" '
        f"n={sequence} src={source_ip}:{source_port}:X1 "
        f'dst={APPLIANCE_IP}:443:X0 usr="{USER_NAME}"'
    )
    return message.encode()


@register_code_rta(
    id="404aec21-f34f-4845-a6e9-c7a8a7d2e6df",
    name="first_seen_sonicwall_remote_access_identity_source",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="7df97e5b-1722-4305-80c7-7a203f2ff36e",
            name="First Seen SonicWall Remote Access Login by User and Source",
        )
    ],
    techniques=["T1078", "T1133"],
)
def main() -> None:
    """Send one first-seen SonicWall SSL VPN login success to the local agent."""
    source_ip = f"203.0.113.{random.randint(1, 254)}"
    source_port = random.randint(49152, 65535)
    event = _build_success_message(source_ip, source_port, 920001)

    log.info(
        "Sending first-seen SonicWall SSL VPN login for %s from %s to %s:%d",
        USER_NAME,
        source_ip,
        SYSLOG_HOST,
        SYSLOG_PORT,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _ = sock.sendto(event, (SYSLOG_HOST, SYSLOG_PORT))

    log.info(
        "Sent login-success event 1080 for serial %s user %s source %s",
        APPLIANCE_SERIAL,
        USER_NAME,
        source_ip,
    )
