# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: RPC (Remote Procedure Call) from the Internet (Linux)
# RTA: linux_rpc_from_internet.py
# Description: Crafts and emits a TCP SYN packet on the wire with a spoofed
#              public source IP and a private (RFC1918) destination IP on
#              TCP/135 (Microsoft DCE/RPC endpoint mapper). This emulates
#              inbound RPC from the Internet to an internal host as captured
#              by a network sensor (Packetbeat network_traffic, Zeek, or
#              PAN-OS).
#
#              Requires CAP_NET_RAW (typically root). The local kernel may
#              drop egress packets with foreign source IPs depending on
#              reverse-path filtering / firewall configuration; the network
#              sensor only needs to observe the packet on the wire to
#              produce the flow event.

import logging
import os
import random
import socket
import struct

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

RPC_PORT = 135
SPOOFED_SOURCE_IP = "8.8.8.8"
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


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + 20
    ident = random.randint(0, 0xFFFF)
    flags_frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, 0, src_bytes, dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, ip_checksum, src_bytes, dst_bytes,
    )

    seq = random.randint(0, 0xFFFFFFFF)
    ack = 0
    data_offset = 5 << 4
    flags = 0x02  # SYN
    window = 8192
    urg_ptr = 0

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, flags, window, 0, urg_ptr,
    )
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_checksum = _ones_complement_sum(pseudo + tcp_header)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, flags, window, tcp_checksum, urg_ptr,
    )

    return ip_header + tcp_header


@register_code_rta(
    id="cd540b73-bfd9-41d2-b68c-e5d7bb0e9f23",
    name="linux_rpc_from_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="143cb236-0956-4f42-a706-814bcaa0cf5a",
            name="RPC (Remote Procedure Call) from the Internet",
        )
    ],
    techniques=["T1133", "T1190"],
)
def main() -> None:
    """Emit a spoofed-source TCP SYN to TCP/135 from a public IP to a private IP."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    src_port = random.randint(1024, 65535)
    packet = _build_syn_packet(SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, src_port, RPC_PORT)

    log.info(
        "Sending spoofed SYN: %s:%d -> %s:%d (RPC from Internet emulation)",
        SPOOFED_SOURCE_IP, src_port, PRIVATE_DESTINATION_IP, RPC_PORT,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        _ = sock.sendto(packet, (PRIVATE_DESTINATION_IP, RPC_PORT))
        log.info("Spoofed SYN emitted")
    except OSError as e:
        log.error("Failed to send spoofed SYN: %s", e)
    finally:
        sock.close()
