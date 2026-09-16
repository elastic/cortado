# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: VNC (Virtual Network Computing) to the Internet (Linux)
# RTA: linux_vnc_to_internet.py
# Description: Initiates outbound TCP connections from the local (presumed
#              RFC1918) host to public Internet IPs on TCP/5800 (VNC HTTP
#              viewer port). This produces a network flow event with source.ip
#              in private space and destination.ip on the public Internet on
#              a VNC port, matching the rule.

import logging
import socket

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

VNC_PORT = 5800
TARGET_PUBLIC_HOSTS = ["8.8.8.8", "1.1.1.1"]


@register_code_rta(
    id="5f20cbd5-55e0-432a-8265-a494b96cb155",
    name="linux_vnc_to_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="3ad49c61-7adc-42c1-b788-732eda2f5abf",
            name="VNC (Virtual Network Computing) to the Internet",
        )
    ],
    techniques=["T1219", "T1021", "T1021.005"],
)
def main() -> None:
    """Generate outbound TCP/5800 traffic from a private host to the public Internet."""
    for host in TARGET_PUBLIC_HOSTS:
        log.info("Attempting outbound VNC connection to %s:%d", host, VNC_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((host, VNC_PORT))
            log.info("VNC connection to %s:%d established", host, VNC_PORT)
        except (socket.timeout, OSError) as e:
            # SYN packet still produces a flow event even on RST/timeout.
            log.info("VNC connection to %s:%d did not complete (%s) - flow event still emitted", host, VNC_PORT, e)
        finally:
            sock.close()
