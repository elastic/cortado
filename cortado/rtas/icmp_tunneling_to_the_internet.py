# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential ICMP Tunneling Activity to the Internet
# RTA: icmp_tunneling_to_the_internet.py
# Description: Crafts and emits raw ICMP Echo requests (type 8) on the wire from
#              an internal RFC1918 source IP to an external public destination,
#              each carrying an oversized data payload. This emulates an ICMP
#              tunneling / covert-channel client (e.g. icmptunnel, ptunnel) that
#              embeds C2 or exfiltrated data in echo payloads far larger than
#              normal OS ping, as captured by a network sensor (Packetbeat
#              network_traffic, Zeek, or PAN-OS) and indexed into
#              logs-network_traffic.icmp-*.
#
#              The source IP (10.10.10.10) is RFC1918 and the destination
#              (8.8.8.8) is public, satisfying the rule's source/destination
#              conditions. Each echo carries a ~512-byte payload so the
#              transaction exceeds the rule's network.bytes >= 256 threshold.
#              ICMP type 8 (IPv4 Echo) is used; type 128 (ICMPv6 Echo) would
#              match the rule equally.
#
#              Requires CAP_NET_RAW (typically root). The local kernel may drop
#              egress packets with a foreign source IP depending on reverse-path
#              filtering; the network sensor only needs to observe the packets
#              on the wire to produce the flow events.

import logging
import os
import random
import socket
import struct

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

ICMP_ECHO_TYPE = 8          # type 128 (ICMPv6 Echo) also matches the rule
INTERNAL_SOURCE_IP = "10.10.10.10"   # RFC1918 source -> satisfies the rule
EXTERNAL_DEST_IP = "8.8.8.8"         # public destination (outside excluded ranges)
TUNNEL_PAYLOAD_LEN = 512             # >= 256 bytes -> exceeds the network.bytes threshold
ECHO_COUNT = 6                       # sustained beacon-like cadence


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    """Build a 20-byte IPv4 header with a correct checksum for an ICMP payload."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    total_len = 20 + payload_len
    ident = random.randint(0, 0xFFFF)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0, 64, socket.IPPROTO_ICMP, 0, src_bytes, dst_bytes,
    )
    checksum = _ones_complement_sum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0, 64, socket.IPPROTO_ICMP, checksum, src_bytes, dst_bytes,
    )


def _build_echo_request(identifier: int, sequence: int, payload: bytes) -> bytes:
    """Build an ICMP Echo request (type 8) with an arbitrary data payload."""
    code = 0
    header = struct.pack("!BBHHH", ICMP_ECHO_TYPE, code, 0, identifier, sequence)
    checksum = _ones_complement_sum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_TYPE, code, checksum, identifier, sequence)
    return header + payload


def _build_packet(identifier: int, sequence: int) -> bytes:
    """Wrap an oversized ICMP Echo request in an IPv4 header from the internal host."""
    # Payload stands in for tunneled/encoded C2 data; size is what matters to the rule.
    payload = bytes(random.randint(0, 255) for _ in range(TUNNEL_PAYLOAD_LEN))
    icmp = _build_echo_request(identifier, sequence, payload)
    ip_header = _build_ip_header(INTERNAL_SOURCE_IP, EXTERNAL_DEST_IP, len(icmp))
    return ip_header + icmp


@register_code_rta(
    id="1ff1de75-c4e0-43a3-b2b7-bed42ba6fad7",
    name="icmp_tunneling_to_the_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="96dd08d8-8f3d-4f55-ada8-7dc1e05dbd47",
            name="Potential ICMP Tunneling Activity to the Internet",
        )
    ],
    techniques=["T1095", "T1572"],
)
def main() -> None:
    """Emit oversized spoofed-source ICMP Echo requests from an internal host to the Internet."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    identifier = random.randint(0, 0xFFFF)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for sequence in range(1, ECHO_COUNT + 1):
            packet = _build_packet(identifier, sequence)
            log.info(
                "Sending oversized ICMP Echo (type %d, %d-byte payload): %s -> %s (ICMP tunneling emulation)",
                ICMP_ECHO_TYPE, TUNNEL_PAYLOAD_LEN, INTERNAL_SOURCE_IP, EXTERNAL_DEST_IP,
            )
            _ = sock.sendto(packet, (EXTERNAL_DEST_IP, 0))
        log.info("Emitted %d oversized ICMP Echo requests", ECHO_COUNT)
    except OSError as e:
        log.error("Failed to send spoofed ICMP packet: %s", e)
    finally:
        sock.close()
