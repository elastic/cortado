# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: ICMP Timestamp or Information Request from the Internet
# RTA: icmp_timestamp_or_information_request_from_the_internet.py
# Description: Crafts and emits a raw ICMP Timestamp request (type 13) on the
#              wire with a spoofed public source IP and a private (RFC1918)
#              destination IP. This emulates an inbound legacy ICMP diagnostic
#              probe from the Internet toward an internal host, as captured by
#              a network sensor (Packetbeat network_traffic, Zeek, or PAN-OS)
#              and indexed into logs-network_traffic.icmp-*.
#
#              The spoofed source IP (8.8.8.8) is a public address that falls
#              outside all RFC1918/special-purpose ranges excluded by the rule.
#              The destination (10.10.10.10) is in 10.0.0.0/8, satisfying the
#              rule's destination.ip condition. ICMP type 13 (Timestamp) is
#              used by default; type 15 (Information) would match equally.
#
#              Requires CAP_NET_RAW (typically root). The local kernel may drop
#              egress packets with a foreign source IP depending on reverse-path
#              filtering; the network sensor only needs to observe the packet on
#              the wire to produce the flow event.

import logging
import os
import random
import socket
import struct

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

ICMP_TIMESTAMP_TYPE = 13  # type 15 (Information request) also matches the rule
INTERNET_SOURCE_IP = "8.8.8.8"
PRIVATE_DESTINATION_IP = "10.10.10.10"


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


def _build_icmp_timestamp(icmp_type: int, identifier: int, sequence: int) -> bytes:
    """Build an ICMP Timestamp request message (type 13)."""
    code = 0
    # Originate / Receive / Transmit timestamps (ms since midnight UT); zeros are valid for a request.
    originate = receive = transmit = 0
    header = struct.pack("!BBHHH", icmp_type, code, 0, identifier, sequence)
    payload = struct.pack("!III", originate, receive, transmit)
    checksum = _ones_complement_sum(header + payload)
    header = struct.pack("!BBHHH", icmp_type, code, checksum, identifier, sequence)
    return header + payload


def _build_packet(src_ip: str, dst_ip: str, icmp_type: int) -> bytes:
    """Wrap an ICMP Timestamp request in an IPv4 header with a spoofed source."""
    icmp = _build_icmp_timestamp(icmp_type, random.randint(0, 0xFFFF), random.randint(0, 0xFFFF))

    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    ip_total_len = 20 + len(icmp)
    ident = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_ICMP, 0, src_bytes, dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_ICMP, ip_checksum, src_bytes, dst_bytes,
    )

    return ip_header + icmp


@register_code_rta(
    id="2dc36312-ebc0-4ea3-a584-013f9a54f3e7",
    name="icmp_timestamp_or_information_request_from_the_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="81139742-4d3a-49f3-a6dd-e0fb9834f959",
            name="ICMP Timestamp or Information Request from the Internet",
        )
    ],
    techniques=["T1016", "T1595", "T1595.001"],
)
def main() -> None:
    """Emit a spoofed-source ICMP Timestamp request from a public IP to a private IP."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    packet = _build_packet(INTERNET_SOURCE_IP, PRIVATE_DESTINATION_IP, ICMP_TIMESTAMP_TYPE)

    log.info(
        "Sending spoofed ICMP type %d: %s -> %s (ICMP Timestamp request from Internet emulation)",
        ICMP_TIMESTAMP_TYPE, INTERNET_SOURCE_IP, PRIVATE_DESTINATION_IP,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        _ = sock.sendto(packet, (PRIVATE_DESTINATION_IP, 0))
        log.info("Spoofed ICMP Timestamp request emitted")
    except OSError as e:
        log.error("Failed to send spoofed ICMP packet: %s", e)
    finally:
        sock.close()
