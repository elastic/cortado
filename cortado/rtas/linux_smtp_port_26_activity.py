# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SMTP on Port 26/TCP (Linux)
# RTA: linux_smtp_port_26_activity.py
# Description: Generates outbound TCP traffic to destination port 26, the
#              alternate SMTP port abused by malware families like BadPatch
#              for command and control. The connection attempt is sufficient
#              to produce a network flow event captured by Packetbeat /
#              network_traffic / Zeek, regardless of whether it succeeds.

import logging
import socket

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SMTP_ALT_PORT = 26
TARGET_HOSTS = ["8.8.8.8", "1.1.1.1"]


@register_code_rta(
    id="aa90b718-800b-4594-84c8-dcc6b3f354a0",
    name="linux_smtp_port_26_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="d7e62693-aab9-4f66-a21a-3d79ecdd603d",
            name="SMTP on Port 26/TCP",
        )
    ],
    techniques=["T1071", "T1071.003", "T1571", "T1048"],
)
def main() -> None:
    """Attempt outbound TCP connections to destination port 26 to mimic SMTP-on-26 C2 traffic."""
    for host in TARGET_HOSTS:
        log.info("Attempting TCP connection to %s:%d (alternate SMTP port)", host, SMTP_ALT_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((host, SMTP_ALT_PORT))
            try:
                _ = sock.send(b"EHLO rta.local\r\n")
            except OSError:
                pass
            log.info("Connection to %s:%d established", host, SMTP_ALT_PORT)
        except (socket.timeout, OSError) as e:
            # A SYN is still emitted even on failure, generating a network flow event.
            log.info("Connection to %s:%d did not complete (%s) - flow event still emitted", host, SMTP_ALT_PORT, e)
        finally:
            sock.close()
