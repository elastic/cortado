# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SMB (Windows File Sharing) Activity from the Internet
# RTA: network_smb_from_internet.py
# Description: Crafts and emits a raw TCP SYN packet on the wire with a
#              spoofed public source IP and a private (RFC1918) destination IP
#              on TCP/445 (SMB/CIFS). This emulates inbound Windows file-sharing
#              traffic from the Internet to an internal host as captured by a
#              network sensor (Packetbeat network_traffic, Zeek, pfSense, or
#              PAN-OS).
#
#              The spoofed source IP (8.8.8.8) is a public address that falls
#              outside all excluded RFC1918/special-purpose ranges in the rule.
#              The destination (10.10.10.10) is in 10.0.0.0/8, satisfying the
#              rule's destination.ip condition.
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

SMB_PORT = 445
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


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build a raw IP/TCP SYN packet."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    seq = random.randint(0, 0xFFFFFFFF)
    data_offset = 5 << 4
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, 0, data_offset, 0x02, 8192, 0, 0,
    )
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_checksum = _ones_complement_sum(pseudo + tcp_header)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, 0, data_offset, 0x02, 8192, tcp_checksum, 0,
    )

    ip_total_len = 20 + len(tcp_header)
    ident = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_TCP, 0, src_bytes, dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_TCP, ip_checksum, src_bytes, dst_bytes,
    )

    return ip_header + tcp_header


@register_code_rta(
    id="ddbaaddc-04eb-44a1-b550-c0084e4284e6",
    name="network_smb_from_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="0ffc3d78-44ce-4a55-b2be-98219e0eed05",
            name="SMB (Windows File Sharing) Activity from the Internet",
        )
    ],
    techniques=["T1133", "T1190"],
)
def main() -> None:
    """Emit a spoofed-source TCP SYN to TCP/445 from a public IP to a private IP."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    src_port = random.randint(1024, 65535)
    packet = _build_syn_packet(INTERNET_SOURCE_IP, PRIVATE_DESTINATION_IP, src_port, SMB_PORT)

    log.info(
        "Sending spoofed SYN: %s:%d -> %s:%d (SMB from Internet emulation)",
        INTERNET_SOURCE_IP, src_port, PRIVATE_DESTINATION_IP, SMB_PORT,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        _ = sock.sendto(packet, (PRIVATE_DESTINATION_IP, SMB_PORT))
        log.info("Spoofed SMB SYN emitted")
    except OSError as e:
        log.error("Failed to send spoofed SYN: %s", e)
    finally:
        sock.close()
