# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Newly Observed IPSEC NAT Traversal Peer (Linux)
# RTA: linux_nat_traversal_port_activity.py
# Description: Emulates an outbound IPSEC NAT Traversal (NAT-T) tunnel by crafting
#              a raw IP/UDP datagram on the wire where BOTH the source and
#              destination port are 4500 — the NAT-T data-channel signature once
#              both peers detect a NAT device. The packet is sent from a spoofed
#              internal (RFC1918) source IP to a randomized public destination IP.
#
#              The rule requires the NAT-T signature specifically:
#                - network.transport: udp
#                - source.port: 4500 AND destination.port: 4500
#                - source.ip in 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16
#                - destination.ip NOT in any private / special-purpose range
#              It groups by destination.ip and alerts only when that peer was
#              first observed within the last 10 minutes across a five-day
#              history window. Randomizing the public destination on every run
#              makes the peer newly observed.
#
#              A plain socket would egress from an ephemeral source port and from
#              the host's own IP (which may be public), so raw packet crafting is
#              required to control both ports and place an internal source IP.
#
#              The UDP payload is a 4-byte non-ESP marker (0x00000000) followed by
#              a short pseudo-IKE blob, matching how NAT-T encapsulates IKE on
#              UDP/4500. The rule keys on transport, ports, and IPs only, so the
#              payload is cosmetic.
#
#              Requires CAP_NET_RAW (run as root or with the capability set). The
#              kernel may drop egress packets carrying a foreign source IP under
#              reverse-path filtering; the network sensor only needs to observe
#              the packet on the wire to produce the flow event.

import logging
import os
import random
import socket
import struct

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

NAT_T_PORT = 4500

# Spoofed internal source so source.ip falls in RFC1918 (rule requirement).
INTERNAL_SOURCE_IP = "10.10.10.10"

# 4-byte non-ESP marker that prefixes IKE messages encapsulated in NAT-T, plus a
# short filler blob so the datagram is non-empty on the wire.
_NAT_T_PAYLOAD = b"\x00\x00\x00\x00" + b"\x11" * 8


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


def _random_public_destination_ip() -> str:
    """Return a randomized address in public 8.0.0.0/8 space."""
    return f"8.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _build_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Build a raw IP/UDP packet with the given source/destination and payload."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    udp_length = 8 + len(payload)
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_UDP, udp_length)
    udp_header_no_csum = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    udp_checksum = _ones_complement_sum(pseudo + udp_header_no_csum + payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    ip_total_len = 20 + udp_length
    ident = random.randint(0, 0xFFFF)
    ip_header_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        ident,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        src_bytes,
        dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header_no_csum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        ident,
        0,
        64,
        socket.IPPROTO_UDP,
        ip_checksum,
        src_bytes,
        dst_bytes,
    )

    return ip_header + udp_header + payload


@register_code_rta(
    id="c4a65e3f-f172-4300-94c1-0f5f9f28213e",
    name="linux_nat_traversal_port_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="a9cb3641-ff4b-4cdc-a063-b4b8d02a67c7",
            name="Newly Observed IPSEC NAT Traversal Peer",
        )
    ],
    techniques=["T1095", "T1572", "T1573"],
)
def main() -> None:
    """Emit a NAT-T datagram from an internal source to a newly observed public peer."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    public_destination_ip = _random_public_destination_ip()
    packet = _build_udp_packet(
        INTERNAL_SOURCE_IP,
        public_destination_ip,
        NAT_T_PORT,
        NAT_T_PORT,
        _NAT_T_PAYLOAD,
    )

    log.info(
        "Sending NAT-T datagram: %s:%d -> %s:%d (IPSEC NAT Traversal emulation)",
        INTERNAL_SOURCE_IP,
        NAT_T_PORT,
        public_destination_ip,
        NAT_T_PORT,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        _ = sock.sendto(packet, (public_destination_ip, NAT_T_PORT))
        log.info("NAT-T flow emitted (source.port=4500, destination.port=4500)")
    except OSError as e:
        log.error("Failed to send NAT-T datagram: %s", e)
    finally:
        sock.close()
