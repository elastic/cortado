# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Network Sweep and Port Scan
# RTA: network_sweep_and_port_scan.py
# Description: Emits two groups of raw TCP SYN packets for network flow sensors:
#              1. One private source probes TCP/445 on 110 documentation-range
#                 destination addresses, satisfying the network-sweep rule.
#              2. One private source probes 260 ports on one documentation-range
#                 destination, satisfying the network and low-packet scan rules.
#
#              TEST-NET-1 destinations are used so the probes cannot reach a
#              real service. Each tuple receives one packet, allowing the
#              Network Packet Capture integration to emit a final low-packet
#              flow after its configured flow timeout.
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

INTERNAL_SOURCE_IP = "10.10.10.50"
SWEEP_DESTINATION_COUNT = 110
SWEEP_DESTINATION_PORT = 445
PORT_SCAN_DESTINATION_IP = "192.0.2.200"
PORT_SCAN_DESTINATION_COUNT = 260
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


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build one IPv4 TCP SYN packet with a spoofed private source."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    sequence = random.randint(0, 0xFFFFFFFF)
    data_offset = 5 << 4

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
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
        dst_port,
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


def _send_syn(sock: socket.socket, dst_ip: str, src_port: int, dst_port: int) -> None:
    packet = _build_syn_packet(INTERNAL_SOURCE_IP, dst_ip, src_port, dst_port)
    _ = sock.sendto(packet, (dst_ip, dst_port))
    time.sleep(PACKET_PAUSE_SECONDS)


@register_code_rta(
    id="21ecce56-4aa4-4527-b35c-914756a112f5",
    name="network_sweep_and_port_scan",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="781f8746-2180-4691-890c-4c96d11ca91d",
            name="Potential Network Sweep Detected",
        ),
        RuleMetadata(
            id="0171f283-ade7-4f87-9521-ac346c68cc9b",
            name="Potential Network Scan Detected",
        ),
        RuleMetadata(
            id="bbaa96b9-f36c-4898-ace2-581acb00a409",
            name="Potential Low-Packet Port Scan Detected",
        ),
    ],
    techniques=["T1018", "T1046", "T1595", "T1595.001"],
)
def main() -> None:
    """Emit distinct-host and distinct-port probe patterns."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        log.info(
            "Emitting %d-host TCP/%d sweep from %s",
            SWEEP_DESTINATION_COUNT,
            SWEEP_DESTINATION_PORT,
            INTERNAL_SOURCE_IP,
        )
        for host in range(1, SWEEP_DESTINATION_COUNT + 1):
            destination_ip = f"192.0.2.{host}"
            _send_syn(
                sock,
                destination_ip,
                40000 + host,
                SWEEP_DESTINATION_PORT,
            )

        log.info(
            "Emitting %d-port scan from %s to %s",
            PORT_SCAN_DESTINATION_COUNT,
            INTERNAL_SOURCE_IP,
            PORT_SCAN_DESTINATION_IP,
        )
        for destination_port in range(1, PORT_SCAN_DESTINATION_COUNT + 1):
            _send_syn(
                sock,
                PORT_SCAN_DESTINATION_IP,
                50000 + destination_port,
                destination_port,
            )

    log.info("Network sweep and port-scan packets emitted")
