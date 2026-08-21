# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Seen Network Flow Exporter
# RTA: first_seen_network_flow_exporter.py
# Description: Sends one NetFlow v5 packet to the Elastic NetFlow integration
#              (UDP/2055). The packet is sourced from a randomized 127.0.0.0/8
#              exporter address so observer.ip is unique in the rule's 30-day
#              new-terms window. NetFlow v5 is used because it is a fixed
#              record format and does not require a prior template.
#
#              This RTA does not require a network device. It must run on a
#              host where Elastic Agent's NetFlow integration listens on the
#              default localhost port 2055. observer.ip is the UDP source of
#              the export, not the addresses inside the flow record.

import logging
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

NETFLOW_HOST = "127.0.0.1"
NETFLOW_PORT = 2055

FLOW_SRC_IP = "192.0.2.1"
FLOW_DST_IP = "192.0.2.2"


def _netflow_v5_packet() -> bytes:
    """Build a single-record NetFlow v5 packet matching Filebeat's v5 layout."""
    uptime_ms = 60_000
    header = struct.pack(
        "!HHIIIIBBH",
        5,
        1,
        uptime_ms,
        int(time.time()),
        0,
        random.randint(1, 0x7FFFFFFF),
        0,
        0,
        0,
    )
    # Filebeat v5 record order after ports: pad, tcp_flags, protocol, ToS.
    record = struct.pack(
        "!4s4s4sHHIIIIHHBBBBHHBBH",
        socket.inet_aton(FLOW_SRC_IP),
        socket.inet_aton(FLOW_DST_IP),
        socket.inet_aton("0.0.0.0"),
        1,
        2,
        10,
        1500,
        uptime_ms - 1_000,
        uptime_ms,
        54321,
        443,
        0,
        0x18,
        6,
        0,
        0,
        0,
        24,
        24,
        0,
    )
    packet = header + record
    if len(packet) != 72:
        raise ValueError(f"NetFlow v5 packet length {len(packet)} != 72")
    return packet


def _exporter_ip() -> str:
    """Pick a loopback exporter address other than 127.0.0.1."""
    return f"127.{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


@register_code_rta(
    id="5af5bad1-b60f-4b48-900c-46d099ac6bbb",
    name="first_seen_network_flow_exporter",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="dfe3f626-4224-417e-aff1-8ef9a72c3191",
            name="First Seen Network Flow Exporter",
        )
    ],
    techniques=["T1562"],
)
def main() -> None:
    """Export one NetFlow v5 record from a first-seen exporter address."""
    exporter_ip = _exporter_ip()
    packet = _netflow_v5_packet()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            sock.bind((exporter_ip, 0))
        except OSError as e:
            log.error("Could not bind NetFlow exporter address %s: %s", exporter_ip, e)
            return
        log.info(
            "Sending NetFlow v5 export from observer.ip=%s to %s:%d",
            exporter_ip,
            NETFLOW_HOST,
            NETFLOW_PORT,
        )
        _ = sock.sendto(packet, (NETFLOW_HOST, NETFLOW_PORT))
        log.info("Sent NetFlow v5 record %s -> %s via exporter %s", FLOW_SRC_IP, FLOW_DST_IP, exporter_ip)
    finally:
        sock.close()
