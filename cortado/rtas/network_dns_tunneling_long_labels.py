# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential DNS Tunneling via Long and Unique Subdomains
# RTA: network_dns_tunneling_long_labels.py
# Description: Emits 25 unique TXT queries under one public registered domain.
#              Each question name has a 52-character encoded subdomain label,
#              which exceeds the rule's subdomain-length gate. NXDOMAIN
#              responses complete the transactions so Packetbeat /
#              network_traffic.dns publishes events without contacting a
#              resolver. The same spoofed client address groups all queries
#              into one five-minute aggregation bucket.
#
#              Requires CAP_NET_RAW. Both packet directions are spoofed.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

DNS_PORT = 53
CLIENT_IP = "10.20.30.40"
SERVER_IP = "10.10.10.10"
REGISTERED_DOMAIN = "example.com"
QUERY_COUNT = 25
SUBDOMAIN_LABEL_LENGTH = 52

_DNS_TYPE_TXT = 16
_DNS_CLASS_IN = 1
_DNS_QUERY_FLAGS = 0x0100
_DNS_NXDOMAIN_FLAGS = 0x8183


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    value = (value & 0xFFFF) + (value >> 16)
    value += value >> 16
    return ~value & 0xFFFF


def _udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_length = 8 + len(payload)
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, socket.IPPROTO_UDP, udp_length)
    udp_zero = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_length, _checksum(pseudo + udp_zero + payload))

    ip_zero = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + udp_length,
        random.randint(0, 0xFFFF),
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        src,
        dst,
    )
    ip = ip_zero[:10] + struct.pack("!H", _checksum(ip_zero)) + ip_zero[12:]
    return ip + udp + payload


def _encode_dns_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        label_bytes = label.encode()
        encoded += bytes([len(label_bytes)]) + label_bytes
    return encoded + b"\x00"


def _dns_message(message_id: int, flags: int, question_name: str) -> bytes:
    header = struct.pack("!HHHHHH", message_id, flags, 1, 0, 0, 0)
    question = _encode_dns_name(question_name) + struct.pack("!HH", _DNS_TYPE_TXT, _DNS_CLASS_IN)
    return header + question


def _question_name(index: int) -> str:
    """Build a unique encoded subdomain whose length is at least 50 characters."""
    label = f"{index:02d}" + ("a1b2c3d4e5" * 5)
    if len(label) != SUBDOMAIN_LABEL_LENGTH:
        raise ValueError(f"encoded label length {len(label)} != {SUBDOMAIN_LABEL_LENGTH}")
    return f"{label}.{REGISTERED_DOMAIN}"


@register_code_rta(
    id="21935d8a-8666-48af-b404-d7fe8b0461e1",
    name="network_dns_tunneling_long_labels",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="89ed957d-609b-4b00-b8c6-a5cbd187632c",
            name="Potential DNS Tunneling via Long and Unique Subdomains",
        )
    ],
    techniques=["T1071", "T1071.004", "T1572", "T1048", "T1048.003"],
)
def main() -> None:
    """Emit unique long-label TXT queries that resemble DNS tunneling."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_port = random.randint(32768, 60000)
    base_id = random.randint(1, 0xFFFF - QUERY_COUNT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    log.info(
        "Emitting %d unique long TXT queries for *.%s from %s",
        QUERY_COUNT,
        REGISTERED_DOMAIN,
        CLIENT_IP,
    )
    try:
        for index in range(QUERY_COUNT):
            name = _question_name(index)
            message_id = base_id + index
            query = _udp_packet(CLIENT_IP, SERVER_IP, client_port, DNS_PORT, _dns_message(message_id, _DNS_QUERY_FLAGS, name))
            response = _udp_packet(
                SERVER_IP,
                CLIENT_IP,
                DNS_PORT,
                client_port,
                _dns_message(message_id, _DNS_NXDOMAIN_FLAGS, name),
            )
            _ = sock.sendto(query, (SERVER_IP, DNS_PORT))
            time.sleep(0.01)
            _ = sock.sendto(response, (CLIENT_IP, client_port))
            time.sleep(0.01)
    finally:
        sock.close()
