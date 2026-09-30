# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Time Seen RMM Service Hostname from Network DNS
# RTA: command_and_control_first_seen_rmm_network_domain.py
# Description: Emits a complete DNS A-record transaction for an exact Atera
#              service hostname. A randomized private client address creates a
#              new source/registered-domain pair for the rule's seven-day
#              history window. Packetbeat / network_traffic.dns decoding of
#              UDP/53 supplies the DNS and source fields used by the rule.
#
#              Requires CAP_NET_RAW. Both packet directions are spoofed, so no
#              recursive resolver or RMM service is contacted.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

DNS_PORT = 53
SERVER_IP = "10.10.10.10"
QUESTION_NAME = "agent-api.atera.com"
ANSWER_IP = "203.0.113.80"
ANSWER_TTL_SECONDS = 60

_DNS_TYPE_A = 1
_DNS_CLASS_IN = 1
_DNS_QUERY_FLAGS = 0x0100
_DNS_RESPONSE_FLAGS = 0x8180
_DNS_NAME_POINTER = 0xC00C


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = sum((data[index] << 8) | data[index + 1] for index in range(0, len(data), 2))
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


def _dns_question() -> bytes:
    return struct.pack("!HH", _DNS_TYPE_A, _DNS_CLASS_IN)


def _dns_header(message_id: int, flags: int, answer_count: int) -> bytes:
    return struct.pack("!HHHHHH", message_id, flags, 1, answer_count, 0, 0)


def _dns_query(message_id: int) -> bytes:
    return _dns_header(message_id, _DNS_QUERY_FLAGS, 0) + _encode_dns_name(QUESTION_NAME) + _dns_question()


def _dns_response(message_id: int) -> bytes:
    answer = struct.pack(
        "!HHHIH4s",
        _DNS_NAME_POINTER,
        _DNS_TYPE_A,
        _DNS_CLASS_IN,
        ANSWER_TTL_SECONDS,
        4,
        socket.inet_aton(ANSWER_IP),
    )
    return (
        _dns_header(message_id, _DNS_RESPONSE_FLAGS, 1)
        + _encode_dns_name(QUESTION_NAME)
        + _dns_question()
        + answer
    )


@register_code_rta(
    id="62a7f013-2621-4489-9197-700ff9c4c23b",
    name="command_and_control_first_seen_rmm_network_domain",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="e73f0535-781b-4a3b-9042-5d993938f8d9",
            name="First Time Seen RMM Service Hostname from Network DNS",
        )
    ],
    techniques=["T1219", "T1219.002"],
)
def main() -> None:
    """Emit one RMM DNS transaction from a randomized client address."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_ip = f"10.200.{random.randint(1, 254)}.{random.randint(1, 254)}"
    client_port = random.randint(32768, 60000)
    message_id = random.randint(1, 0xFFFF)
    query = _udp_packet(client_ip, SERVER_IP, client_port, DNS_PORT, _dns_query(message_id))
    response = _udp_packet(SERVER_IP, client_ip, DNS_PORT, client_port, _dns_response(message_id))

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    log.info("Emitting DNS transaction for %s from new client %s", QUESTION_NAME, client_ip)
    try:
        _ = sock.sendto(query, (SERVER_IP, DNS_PORT))
        time.sleep(0.01)
        _ = sock.sendto(response, (client_ip, client_port))
    finally:
        sock.close()
