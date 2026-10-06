# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious Linux Process Connection to AWS IoT Core MQTT
# RTA: command_and_control_suspicious_linux_process_aws_iot_mqtt.py
# Description: Runs one Linux process from /tmp whose name starts with a dot.
#              That process resolves a synthetic AWS IoT Core ATS name and then
#              attempts an outbound TCP connection to a public address on
#              TCP/443. Elastic Defend attributes both events to the same
#              process.entity_id, which is the sequence the rule requires.
#
#              The executable path matches /tmp/* and the process name matches
#              the hidden-name clause. The DNS question matches
#              *-ats.iot.*.amazonaws.com. The name is not a real AWS IoT
#              endpoint, and the connection is not made to a resolved broker
#              address. The rule correlates the lookup with any later public
#              connection on TCP/443 or TCP/8883; this run uses TCP/443 so the
#              attempt can complete against a public listener.
#
#              Linux DNS events require Elastic Defend on Stack 9.3.0 or later.

import logging
import sys
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

SUSPICIOUS_EXECUTABLE = "/tmp/.cortado-aws-iot"
AWS_IOT_ATS_NAME = "cortado-ats.iot.us-east-1.amazonaws.com"
PUBLIC_DESTINATION_IP = "8.8.8.8"
DESTINATION_PORT = 443

# argv after -c: DNS name, destination IP, destination port.
_CHILD_CODE = """
import socket
import sys

name = sys.argv[1]
destination = sys.argv[2]
port = int(sys.argv[3])
try:
    socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)
except OSError:
    pass
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
    """Look up a synthetic AWS IoT ATS name and connect outbound from /tmp."""
    source = _elf_interpreter()
    if source is None:
        return

    _common.copy_file(source, SUSPICIOUS_EXECUTABLE)
    try:
        _ = _common.execute_command(["chmod", "+x", SUSPICIOUS_EXECUTABLE])
        log.info(
            "Resolving %s and connecting to %s:%d from %s",
            AWS_IOT_ATS_NAME,
            PUBLIC_DESTINATION_IP,
            DESTINATION_PORT,
            SUSPICIOUS_EXECUTABLE,
        )
        _ = _common.execute_command(
            [
                SUSPICIOUS_EXECUTABLE,
                "-c",
                _CHILD_CODE,
                AWS_IOT_ATS_NAME,
                PUBLIC_DESTINATION_IP,
                str(DESTINATION_PORT),
            ],
            timeout_secs=15,
        )
        log.info("Suspicious AWS IoT lookup and connection attempt emitted")
    finally:
        _common.remove_file(SUSPICIOUS_EXECUTABLE)
