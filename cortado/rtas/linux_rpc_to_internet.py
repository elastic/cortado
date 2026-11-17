# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: RPC (Remote Procedure Call) to the Internet (Linux)
# RTA: linux_rpc_to_internet.py
# Description: Emits a complete synthetic TCP session from an RFC1918 source
#              to a public destination on TCP/135 through the monitored
#              physical interface. Ethernet frames are addressed back to the
#              local adapter, so no traffic is routed to the public endpoint.

import logging
import random

from . import OSType, RuleMetadata, register_code_rta
from ._synthetic_tcp import (
    SyntheticTcpError,
    build_tcp_exchange,
    configured_interface,
    emit_frames,
    interface_mac_address,
)

log = logging.getLogger(__name__)

RPC_PORT = 135
PRIVATE_SOURCE_IP = "10.10.10.10"
PUBLIC_DESTINATION_IP = "8.8.8.8"


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
    """Emit an established, multi-packet private-to-public TCP/135 flow."""
    try:
        interface = configured_interface()
        frames = build_tcp_exchange(
            source_ip=PRIVATE_SOURCE_IP,
            destination_ip=PUBLIC_DESTINATION_IP,
            source_port=random.randint(49152, 65535),
            destination_port=RPC_PORT,
            mac_address=interface_mac_address(interface),
            client_payload=b"CORTADO RPC endpoint mapper request",
            server_payload=b"CORTADO RPC endpoint mapper response",
        )
        log.info(
            "Emitting established RPC session %s -> %s:%d on %s",
            PRIVATE_SOURCE_IP,
            PUBLIC_DESTINATION_IP,
            RPC_PORT,
            interface,
        )
        emit_frames(frames, interface=interface)
    except SyntheticTcpError as error:
        log.error("Unable to emit RPC session: %s", error)
