# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: NetScaler Superuser Binding Followed by Authentication Control Removal
# RTA: persistence_netscaler_superuser_binding_followed_by_authentication_control_removal.py
# Description: Sends two synthetic native NetScaler CMD_EXECUTED syslog events:
#              a system-user binding to the built-in superuser policy followed
#              by an endpoint-analysis action whose default group is NO_AUTH.
#              The command text is only logged; no NetScaler command executes.
#
#              This RTA does not require a NetScaler appliance. It must run on a
#              host where Elastic Agent's Citrix ADC integration listens for UDP
#              syslog on the default localhost port 9521.

import logging
import socket
import time
from datetime import UTC, datetime

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 9521
SYSLOG_PRI = 134

APPLIANCE_HOSTNAME = "rta-netscaler"
REMOTE_IP = "192.0.2.10"
USER = "rta-admin"
FIRST_EVENT_ID = 990002
SUPERUSER_COMMAND = "bind system user elastic-rta-backup superuser"
AUTH_CONTROL_COMMAND = "set authentication epaAction elastic-rta-epa -defaultEPAGroup NO_AUTH"


def _build_cmd_executed_message(now: datetime, event_id: int, command: str) -> bytes:
    """Build a native NetScaler CLI CMD_EXECUTED syslog record."""
    native_time = now.strftime("%m/%d/%Y:%H:%M:%S")
    message = (
        f"<{SYSLOG_PRI}> {native_time} GMT {APPLIANCE_HOSTNAME} 0-PPE-0 : "
        f"default CLI CMD_EXECUTED {event_id} 0 : "
        f'User {USER} - ADM_User NONE - Remote_ip {REMOTE_IP} - '
        f'Command "{command}" - Status "Success"'
    )
    return message.encode()


@register_code_rta(
    id="f45bac7d-d5d9-4378-a81a-544bf9c46c65",
    name="persistence_netscaler_superuser_binding_followed_by_authentication_control_removal",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="8d99345f-7e67-4d50-9958-eca162251133",
            name="NetScaler Superuser Binding Followed by Authentication Control Removal",
        )
    ],
    techniques=["T1136", "T1136.001", "T1556", "T1556.004"],
)
def main() -> None:
    """Send the ordered synthetic NetScaler command sequence."""
    commands = (SUPERUSER_COMMAND, AUTH_CONTROL_COMMAND)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for offset, command in enumerate(commands):
            event_id = FIRST_EVENT_ID + offset
            event = _build_cmd_executed_message(datetime.now(UTC), event_id, command)

            log.info(
                "Sending synthetic NetScaler CMD_EXECUTED event %d to %s:%d",
                event_id,
                SYSLOG_HOST,
                SYSLOG_PORT,
            )
            _ = sock.sendto(event, (SYSLOG_HOST, SYSLOG_PORT))

            if offset == 0:
                time.sleep(0.1)

    log.info("Sent synthetic NetScaler superuser and authentication-control sequence")
