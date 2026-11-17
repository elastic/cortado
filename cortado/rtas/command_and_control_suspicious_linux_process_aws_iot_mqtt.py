# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious Linux Process Connection to AWS IoT Core MQTT
# RTA: command_and_control_suspicious_linux_process_aws_iot_mqtt.py
# Description: Runs one Linux process from /tmp whose name starts with a dot.
#              That process resolves an AWS IoT Core ATS name and then attempts
#              an outbound TCP connection to one of the returned addresses on
#              TCP/443. Elastic Defend attributes both events to the same
#              process.entity_id, which is the sequence the rule requires.
#
#              The executable path matches /tmp/* and the process name matches
#              the hidden-name clause. The DNS question matches
#              *-ats.iot.*.amazonaws.com. The connection uses an IPv4 address
#              returned by that lookup, satisfying the rule's DNS answer to
#              destination IP correlation.
#
#              Linux DNS events require Elastic Defend on Stack 9.3.0 or later.

import logging
import sys
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

SUSPICIOUS_EXECUTABLE = "/tmp/.cortado-aws-iot"
# Public endpoint used by Espressif's AWS IoT tutorial.
AWS_IOT_ATS_NAME = "a3orti3lw2padm-ats.iot.us-east-1.amazonaws.com"
DESTINATION_PORT = 443

# argv after -c: DNS name, destination port.
_CHILD_CODE = """
import socket
import sys

name = sys.argv[1]
port = int(sys.argv[2])
try:
    answers = socket.getaddrinfo(
        name,
        port,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
except OSError as error:
    raise SystemExit(f"Could not resolve {name}: {error}") from error

destination = answers[0][4][0]
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
try:
    sock.connect((destination, port))
except OSError:
    pass
finally:
    sock.close()
"""


def _elf_interpreter() -> Path | None:
    """Return the running interpreter when it is a real Linux ELF."""
    source = Path(sys.executable).resolve()
    try:
        magic = source.read_bytes()[:4]
    except OSError as e:
        log.error("Could not read interpreter %s: %s", source, e)
        return None
    if magic != b"\x7fELF":
        log.error("Interpreter %s is not a Linux ELF", source)
        return None
    return source


@register_code_rta(
    id="86352fbe-5130-4c1c-9daa-4e62b584fe3e",
    name="command_and_control_suspicious_linux_process_aws_iot_mqtt",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="3c92b53d-3376-4c79-86fb-7e785fe8d882",
            name="Suspicious Linux Process Connection to AWS IoT Core MQTT",
        )
    ],
    techniques=["T1071", "T1071.005"],
)
def main() -> None:
    """Look up an AWS IoT ATS name and connect to its resolved IP from /tmp."""
    source = _elf_interpreter()
    if source is None:
        return

    _common.copy_file(source, SUSPICIOUS_EXECUTABLE)
    try:
        _ = _common.execute_command(["chmod", "+x", SUSPICIOUS_EXECUTABLE])
        log.info(
            "Resolving %s and connecting to one of its addresses on TCP/%d from %s",
            AWS_IOT_ATS_NAME,
            DESTINATION_PORT,
            SUSPICIOUS_EXECUTABLE,
        )
        _ = _common.execute_command(
            [
                SUSPICIOUS_EXECUTABLE,
                "-c",
                _CHILD_CODE,
                AWS_IOT_ATS_NAME,
                str(DESTINATION_PORT),
            ],
            timeout_secs=15,
        )
        log.info("Suspicious AWS IoT lookup and connection attempt emitted")
    finally:
        _common.remove_file(SUSPICIOUS_EXECUTABLE)
