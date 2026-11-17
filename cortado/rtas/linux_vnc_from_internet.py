# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: VNC (Virtual Network Computing) from the Internet (Linux)
# RTA: linux_vnc_from_internet.py
# Description: Emits a complete synthetic TCP session from a public source to
#              an RFC1918 destination on TCP/5800 through the monitored
#              physical interface. Ethernet frames are addressed back to the
#              local adapter, so neither endpoint is contacted or exposed.

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

VNC_PORT = 5800
PUBLIC_SOURCE_IP = "8.8.8.8"
PRIVATE_DESTINATION_IP = "10.10.10.10"


@register_code_rta(
    id="6e53c4a9-09b6-4502-89c8-4db32e75305e",
    name="linux_vnc_from_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="5700cb81-df44-46aa-a5d7-337798f53eb8",
            name="VNC (Virtual Network Computing) from the Internet",
        )
    ],
    techniques=["T1219", "T1133", "T1190"],
)
def main() -> None:
    """Emit an established, multi-packet public-to-private TCP/5800 flow."""
    try:
        interface = configured_interface()
        frames = build_tcp_exchange(
            source_ip=PUBLIC_SOURCE_IP,
            destination_ip=PRIVATE_DESTINATION_IP,
            source_port=random.randint(49152, 65535),
            destination_port=VNC_PORT,
            mac_address=interface_mac_address(interface),
            client_payload=b"RFB 003.008\n",
            server_payload=b"RFB 003.008\n",
        )
        log.info(
            "Emitting established VNC session %s -> %s:%d on %s",
            PUBLIC_SOURCE_IP,
            PRIVATE_DESTINATION_IP,
            VNC_PORT,
            interface,
        )
        emit_frames(frames, interface=interface)
    except SyntheticTcpError as error:
        log.error("Unable to emit VNC session: %s", error)
