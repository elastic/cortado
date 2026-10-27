# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: High-Cardinality External TCP Fan-In
# RTA: network_high_cardinality_tcp_fan_in.py
# Description: Emits 520 one-packet TCP flows from 52 distinct spoofed public
#              source addresses to one private destination on TCP/27017. This
#              satisfies both fan-in rules by exceeding their distinct-source
#              and completed-flow thresholds while keeping every flow at one
#              packet.
#
#              The packets contain only TCP SYN headers and do not complete a
#              connection. Network Packet Capture emits the qualifying final
#              flow records after its configured flow timeout.
#
#              Requires CAP_NET_RAW (typically root) and a network sensor that
#              captures the emitted packets with flow reporting enabled.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

PRIVATE_DESTINATION_IP = "10.255.255.254"
DESTINATION_PORT = 27017
DISTINCT_SOURCE_COUNT = 52
FLOWS_PER_SOURCE = 10
PACKET_PAUSE_SECONDS = 0.002


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = 0
    for index in range(0, len(data), 2):
        value += (data[index] << 8) | data[index + 1]
    value = (value & 0xFFFF) + (value >> 16)
    value += value >> 16
    return ~value & 0xFFFF


def _build_syn_packet(src_ip: str, src_port: int) -> bytes:
    """Build one IPv4 TCP SYN packet for the fixed fan-in destination."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(PRIVATE_DESTINATION_IP)
    sequence = random.randint(0, 0xFFFFFFFF)
    data_offset = 5 << 4

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        DESTINATION_PORT,
        sequence,
        0,
        data_offset,
        0x02,
        8192,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_bytes,
        dst_bytes,
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    tcp_checksum = _ones_complement_sum(pseudo_header + tcp_header)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        DESTINATION_PORT,
        sequence,
        0,
        data_offset,
        0x02,
        8192,
        tcp_checksum,
        0,
    )

    total_length = 20 + len(tcp_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        random.randint(0, 0xFFFF),
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        src_bytes,
        dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]
    return ip_header + tcp_header


@register_code_rta(
    id="8196a48a-169a-48e8-a4b8-031c96e85780",
    name="network_high_cardinality_tcp_fan_in",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="530e82e6-11bc-4c9b-9e33-a2eeebbefe8d",
            name="High-Cardinality External Low-Packet TCP Fan-In",
        ),
        RuleMetadata(
            id="4f342748-b3ea-4f62-a35a-315afd97c94e",
            name="Multiple External Sources Accessing TCP Port 27017",
        ),
    ],
    techniques=["T1595"],
)
def main() -> None:
    """Emit the external-source TCP fan-in pattern."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    total_flows = DISTINCT_SOURCE_COUNT * FLOWS_PER_SOURCE
    log.info(
        "Emitting %d one-packet flows from %d sources to %s:%d",
        total_flows,
        DISTINCT_SOURCE_COUNT,
        PRIVATE_DESTINATION_IP,
        DESTINATION_PORT,
    )

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        for source_host in range(1, DISTINCT_SOURCE_COUNT + 1):
            source_ip = f"8.8.8.{source_host}"
            for flow_index in range(FLOWS_PER_SOURCE):
                source_port = 40000 + (source_host * FLOWS_PER_SOURCE) + flow_index
                packet = _build_syn_packet(source_ip, source_port)
                _ = sock.sendto(packet, (PRIVATE_DESTINATION_IP, DESTINATION_PORT))
                time.sleep(PACKET_PAUSE_SECONDS)

    log.info("High-cardinality TCP fan-in packets emitted")
