# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential SIP REGISTER Brute Force
# RTA: network_sip_register_brute_force.py
# Description: Emits ten complete SIP REGISTER transactions for extension 1001,
#              each ending in a 401 Unauthorized response. This exceeds the
#              rule's targeted-extension threshold while preserving realistic
#              Via, Call-ID, CSeq, From, and To headers for SIP decoding.
#
#              Requires CAP_NET_RAW. Both request and response packets are
#              spoofed, so no PBX or SIP endpoint is required.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SIP_PORT = 5060
FAILURE_COUNT = 10
CLIENT_IP = "10.20.30.40"
SERVER_IP = "10.10.10.10"
EXTENSION = "1001"


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


def _register_messages(sequence: int, client_port: int) -> tuple[bytes, bytes]:
    branch = f"z9hG4bK-rta-{sequence:04d}"
    call_id = f"rta-register-{sequence:04d}@{CLIENT_IP}"
    common_headers = (
        f"Via: SIP/2.0/UDP {CLIENT_IP}:{client_port};branch={branch}\r\n"
        f"From: <sip:{EXTENSION}@pbx.example>;tag=rta-client\r\n"
        f"To: <sip:{EXTENSION}@pbx.example>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {sequence} REGISTER\r\n"
    )
    request = (
        "REGISTER sip:pbx.example SIP/2.0\r\n"
        f"{common_headers}"
        f"Contact: <sip:{EXTENSION}@{CLIENT_IP}:{client_port}>\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()
    response = (
        "SIP/2.0 401 Unauthorized\r\n"
        f"{common_headers}"
        'WWW-Authenticate: Digest realm="pbx.example", nonce="rta-invalid"\r\n'
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()
    return request, response


@register_code_rta(
    id="49215902-09e3-4dbd-aab7-48cac57aac31",
    name="network_sip_register_brute_force",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="1ca59146-7386-4033-a010-1c32717e9321",
            name="Potential SIP REGISTER Brute Force",
        )
    ],
    techniques=["T1110"],
)
def main() -> None:
    """Emit ten rejected SIP REGISTER transactions for one extension."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_port = random.randint(32768, 60000)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    log.info(
        "Emitting %d rejected SIP REGISTER transactions for extension %s",
        FAILURE_COUNT,
        EXTENSION,
    )
    try:
        for sequence in range(1, FAILURE_COUNT + 1):
            request_body, response_body = _register_messages(sequence, client_port)
            request = _udp_packet(CLIENT_IP, SERVER_IP, client_port, SIP_PORT, request_body)
            response = _udp_packet(SERVER_IP, CLIENT_IP, SIP_PORT, client_port, response_body)
            _ = sock.sendto(request, (SERVER_IP, SIP_PORT))
            time.sleep(0.01)
            _ = sock.sendto(response, (CLIENT_IP, client_port))
            time.sleep(0.01)
    finally:
        sock.close()
