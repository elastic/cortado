# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SMTP to the Internet on Port 26/TCP (Linux)
# RTA: linux_smtp_port_26_activity.py
# Description: Emulates outbound SMTP-on-26 command-and-control traffic (abused by
#              malware families such as BadPatch) by crafting a raw IP/TCP SYN on
#              the wire to TCP/26, from a spoofed internal (RFC1918) source IP to a
#              public (external) destination IP.
#
#              The updated rule is scoped to outbound traffic:
#                - network.transport: tcp
#                - destination.port: 26
#                - source.ip in 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16
#                - destination.ip NOT in any private / special-purpose range
#              A plain socket would egress from the host's own IP (which may be
#              public), so raw packet crafting is used to guarantee an internal
#              source IP and external destination regardless of the host's address.
#
#              A single SYN is enough for the network sensor (Packetbeat /
#              network_traffic / Zeek) to record the flow event, so no completed
#              handshake is required.
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

SMTP_ALT_PORT = 26

# Spoofed internal source so source.ip falls in RFC1918 (rule requirement).
INTERNAL_SOURCE_IP = "10.10.10.10"
# Public destination outside all excluded private / special-purpose ranges.
PUBLIC_DESTINATION_IP = "8.8.8.8"


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
    id="aa90b718-800b-4594-84c8-dcc6b3f354a0",
    name="linux_smtp_port_26_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="d7e62693-aab9-4f66-a21a-3d79ecdd603d",
            name="SMTP to the Internet on Port 26/TCP",
        )
    ],
    techniques=["T1071", "T1071.003", "T1571", "T1048"],
)
def main() -> None:
    """Emit a raw TCP SYN to TCP/26 from an internal source IP to a public destination IP."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    src_port = random.randint(1024, 65535)
    packet = _build_syn_packet(INTERNAL_SOURCE_IP, PUBLIC_DESTINATION_IP, src_port, SMTP_ALT_PORT)

    log.info(
        "Sending SYN: %s:%d -> %s:%d (SMTP-on-26 to the Internet emulation)",
        INTERNAL_SOURCE_IP, src_port, PUBLIC_DESTINATION_IP, SMTP_ALT_PORT,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        _ = sock.sendto(packet, (PUBLIC_DESTINATION_IP, SMTP_ALT_PORT))
        log.info("SMTP-on-26 SYN emitted (internal source -> public destination)")
    except OSError as e:
        log.error("Failed to send SYN: %s", e)
    finally:
        sock.close()
