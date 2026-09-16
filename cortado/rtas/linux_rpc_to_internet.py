# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: RPC (Remote Procedure Call) to the Internet (Linux)
# RTA: linux_rpc_to_internet.py
# Description: Initiates outbound TCP connections from the local (presumed
#              RFC1918) host to public Internet IPs on TCP/135 (Microsoft
#              DCE/RPC endpoint mapper). The connection attempt produces a
#              network flow event with source.ip in private space and
#              destination.ip on the public Internet, matching the rule.

import logging
import socket

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

RPC_PORT = 135
TARGET_PUBLIC_HOSTS = ["8.8.8.8", "1.1.1.1"]


@register_code_rta(
    id="cda587a3-aa98-4fb4-8dcb-662ca8c558a4",
    name="linux_rpc_to_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="32923416-763a-4531-bb35-f33b9232ecdb",
            name="RPC (Remote Procedure Call) to the Internet",
        )
    ],
    techniques=["T1190", "T1021", "T1021.003"],
)
def main() -> None:
    """Generate outbound TCP/135 (DCE/RPC) traffic from a private host to the public Internet."""
    for host in TARGET_PUBLIC_HOSTS:
        log.info("Attempting outbound RPC connection to %s:%d", host, RPC_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((host, RPC_PORT))
            log.info("RPC connection to %s:%d established", host, RPC_PORT)
        except (socket.timeout, OSError) as e:
            # SYN packet still produces a flow event even on RST/timeout.
            log.info("RPC connection to %s:%d did not complete (%s) - flow event still emitted", host, RPC_PORT, e)
        finally:
            sock.close()
