# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SMB (Windows File Sharing) Activity to the Internet (Linux)
# RTA: linux_smb_to_internet.py
# Description: Initiates outbound TCP connections from the local (presumed
#              RFC1918) host to public Internet IPs on TCP/139 and TCP/445
#              (NetBIOS Session Service / SMB over TCP). This produces a
#              network flow event with source.ip in private space and
#              destination.ip on the public Internet on SMB ports.

import logging
import socket

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SMB_PORTS = [139, 445]
TARGET_PUBLIC_HOSTS = ["8.8.8.8", "1.1.1.1"]


@register_code_rta(
    id="1176cb6d-3652-4f3c-a6b7-949b1aefdfe8",
    name="linux_smb_to_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="c82b2bd8-d701-420c-ba43-f11a155b681a",
            name="SMB (Windows File Sharing) Activity to the Internet",
        )
    ],
    techniques=["T1190", "T1048"],
)
def main() -> None:
    """Generate outbound TCP/139 and TCP/445 traffic from a private host to the public Internet."""
    for host in TARGET_PUBLIC_HOSTS:
        for port in SMB_PORTS:
            log.info("Attempting outbound SMB connection to %s:%d", host, port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            try:
                sock.connect((host, port))
                log.info("SMB connection to %s:%d established", host, port)
            except (socket.timeout, OSError) as e:
                # SYN packet still produces a flow event even on RST/timeout.
                log.info("SMB connection to %s:%d did not complete (%s) - flow event still emitted", host, port, e)
            finally:
                sock.close()
