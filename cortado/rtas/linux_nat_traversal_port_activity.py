# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: IPSEC NAT Traversal Port Activity (Linux)
# RTA: linux_nat_traversal_port_activity.py
# Description: Sends a UDP datagram to a public Internet host on UDP/4500
#              (IPSEC NAT Traversal / IKE NAT-T). The send attempt produces
#              a network flow event regardless of whether the remote host
#              responds, matching the rule which only checks for
#              network.transport:udp and destination.port:4500.

import logging
import socket

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

NAT_T_PORT = 4500
TARGET_PUBLIC_HOSTS = ["8.8.8.8", "1.1.1.1"]


@register_code_rta(
    id="c4a65e3f-f172-4300-94c1-0f5f9f28213e",
    name="linux_nat_traversal_port_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="a9cb3641-ff4b-4cdc-a063-b4b8d02a67c7",
            name="IPSEC NAT Traversal Port Activity",
        )
    ],
    techniques=["T1095", "T1572", "T1573"],
)
def main() -> None:
    """Send UDP datagrams to UDP/4500 (IPSEC NAT-T) on public Internet hosts."""
    for host in TARGET_PUBLIC_HOSTS:
        log.info("Sending UDP datagram to %s:%d (IPSEC NAT-T)", host, NAT_T_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            _ = sock.sendto(b"\x00" * 4, (host, NAT_T_PORT))
            log.info("UDP datagram to %s:%d sent - flow event emitted", host, NAT_T_PORT)
        except OSError as e:
            log.error("Failed to send UDP datagram to %s:%d: %s", host, NAT_T_PORT, e)
        finally:
            sock.close()
