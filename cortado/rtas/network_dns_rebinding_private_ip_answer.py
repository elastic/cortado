# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential DNS Rebinding from Public to Private Address
# RTA: network_dns_rebinding_private_ip_answer.py
# Description: Emits a complete DNS A-record transaction for a public registered
#              domain whose NOERROR response contains both a public address and
#              a link-local cloud-metadata address. Packetbeat /
#              network_traffic.dns decoding of UDP/53 produces one event with
#              both address classes in dns.resolved_ip, matching the rule's
#              same-response rebinding pattern.
#
#              Requires CAP_NET_RAW. Both packet directions are spoofed, so no
#              recursive resolver or attacker name server is contacted.

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
QUESTION_NAME = "imds.rta-rebinding.example.com"
PUBLIC_ANSWER_IP = "203.0.113.80"
PRIVATE_ANSWER_IP = "169.254.169.254"
ANSWER_TTL_SECONDS = 1

_DNS_TYPE_A = 1
_DNS_CLASS_IN = 1
_DNS_QUERY_FLAGS = 0x0100
_DNS_RESPONSE_FLAGS = 0x8180
_DNS_NAME_POINTER = 0xC00C


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


def _dns_question() -> bytes:
    return struct.pack("!HH", _DNS_TYPE_A, _DNS_CLASS_IN)


def _dns_header(message_id: int, flags: int, question_count: int, answer_count: int) -> bytes:
    return struct.pack("!HHHHHH", message_id, flags, question_count, answer_count, 0, 0)


def _dns_a_record(ipv4: str) -> bytes:
    return struct.pack(
        "!HHHIH4s",
        _DNS_NAME_POINTER,
        _DNS_TYPE_A,
        _DNS_CLASS_IN,
        ANSWER_TTL_SECONDS,
        4,
        socket.inet_aton(ipv4),
    )


def _dns_query(message_id: int) -> bytes:
    return _dns_header(message_id, _DNS_QUERY_FLAGS, 1, 0) + _encode_dns_name(QUESTION_NAME) + _dns_question()


def _dns_response(message_id: int) -> bytes:
    return (
        _dns_header(message_id, _DNS_RESPONSE_FLAGS, 1, 2)
        + _encode_dns_name(QUESTION_NAME)
        + _dns_question()
        + _dns_a_record(PUBLIC_ANSWER_IP)
        + _dns_a_record(PRIVATE_ANSWER_IP)
    )


@register_code_rta(
    id="4e3b6c97-b4ab-407f-bb03-9ba1994c3d08",
    name="network_dns_rebinding_private_ip_answer",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="c485ceb7-b0e3-4540-9e8c-e9c655406e68",
            name="Potential DNS Rebinding from Public to Private Address",
        )
    ],
    techniques=["T1189"],
)
def main() -> None:
    """Emit a DNS response that answers a public name with public and private A records."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_port = random.randint(32768, 60000)
    message_id = random.randint(1, 0xFFFF)
    query = _udp_packet(CLIENT_IP, SERVER_IP, client_port, DNS_PORT, _dns_query(message_id))
    response = _udp_packet(SERVER_IP, CLIENT_IP, DNS_PORT, client_port, _dns_response(message_id))

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    log.info(
        "Emitting DNS rebinding answers for %s: public=%s private=%s ttl=%d",
        QUESTION_NAME,
        PUBLIC_ANSWER_IP,
        PRIVATE_ANSWER_IP,
        ANSWER_TTL_SECONDS,
    )
    try:
        _ = sock.sendto(query, (SERVER_IP, DNS_PORT))
        time.sleep(0.01)
        _ = sock.sendto(response, (CLIENT_IP, client_port))
    finally:
        sock.close()
