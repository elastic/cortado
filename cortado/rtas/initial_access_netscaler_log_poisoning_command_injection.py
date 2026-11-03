# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential NetScaler Log Poisoning Command Injection Attempt
# RTA: initial_access_netscaler_log_poisoning_command_injection.py
# Description: Sends one synthetic native NetScaler PITBOSS syslog event whose
#              message combines packet-engine terminology with shell syntax.
#              The Citrix ADC integration parses the event into
#              citrix.device_event_class_id and citrix_adc.log.message, matching
#              the detection rule without exploiting a NetScaler appliance or
#              executing the command-like text.
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
EVENT_ID = 990001


def _build_pitboss_message(now: datetime) -> bytes:
    """Build a native NetScaler PITBOSS record containing inert shell text."""
    native_time = now.strftime("%m/%d/%Y:%H:%M:%S")
    message = (
        f"<{SYSLOG_PRI}> {native_time}  {APPLIANCE_HOSTNAME} 0-PPE-0 : "
        f"default PITBOSS PPE_FAILURE {EVENT_ID} 2 :  "
        "pitboss PPE 0 unexpectedly died; NSPPE-0; /bin/echo elastic-rta"
    )
    return message.encode()


@register_code_rta(
    id="6f47ac6d-8456-45b4-a8af-8716a61b0b61",
    name="initial_access_netscaler_log_poisoning_command_injection",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="afaece21-6631-440b-87d3-1d0a2013576e",
            name="Potential NetScaler Log Poisoning Command Injection Attempt",
        )
    ],
    techniques=["T1190"],
)
def main() -> None:
    """Send one synthetic NetScaler PITBOSS event to the local agent."""
    event = _build_pitboss_message(datetime.now(UTC))

    log.info(
        "Sending synthetic NetScaler PITBOSS event to %s:%d",
        SYSLOG_HOST,
        SYSLOG_PORT,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _ = sock.sendto(event, (SYSLOG_HOST, SYSLOG_PORT))

    log.info("Sent PITBOSS event %d with inert command-like text", EVENT_ID)
