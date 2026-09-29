# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential SIP Extension Enumeration
# RTA: network_sip_extension_enumeration.py
# Description: Emits SIP OPTIONS requests for 20 distinct sequential extensions
#              from one client to one PBX. A matching 404 response completes
#              each SIP transaction, and a SIPvicious-style User-Agent makes
#              the emulated reconnaissance recognizable during triage.
#
#              Requires CAP_NET_RAW. Both packet directions are spoofed and no
#              live PBX is contacted.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

SIP_PORT = 5060
EXTENSION_COUNT = 20
CLIENT_IP = "10.20.30.40"
SERVER_IP = "10.10.10.10"


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


def _options_messages(sequence: int, extension: str, client_port: int) -> tuple[bytes, bytes]:
    branch = f"z9hG4bK-enum-{sequence:04d}"
    call_id = f"rta-options-{sequence:04d}@{CLIENT_IP}"
    common = (
        f"Via: SIP/2.0/UDP {CLIENT_IP}:{client_port};branch={branch}\r\n"
        f"From: <sip:scanner@scanner.invalid>;tag=rta-enum\r\n"
        f"To: <sip:{extension}@pbx.example>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {sequence} OPTIONS\r\n"
    )
    request = (
        f"OPTIONS sip:{extension}@pbx.example SIP/2.0\r\n"
        f"{common}"
        "Max-Forwards: 70\r\n"
        "User-Agent: friendly-scanner/1.0\r\n"
        "Accept: application/sdp\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()
    response = (
        "SIP/2.0 404 Not Found\r\n"
        f"{common}"
        "Server: rta-pbx\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()
    return request, response


@register_code_rta(
    id="6818ed6f-b34e-4afe-a825-d0d0991afec5",
    name="network_sip_extension_enumeration",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="e7bf9314-f346-45b5-a6ed-044dc3b839c8",
            name="Potential SIP Extension Enumeration",
        )
    ],
    techniques=["T1087", "T1595"],
)
def main() -> None:
    """Emit OPTIONS transactions for 20 distinct SIP extensions."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_port = random.randint(32768, 60000)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    log.info("Emitting SIP OPTIONS enumeration across %d extensions", EXTENSION_COUNT)
    try:
        for sequence in range(1, EXTENSION_COUNT + 1):
            extension = str(1000 + sequence)
            request_body, response_body = _options_messages(sequence, extension, client_port)
            request = _udp_packet(CLIENT_IP, SERVER_IP, client_port, SIP_PORT, request_body)
            response = _udp_packet(SERVER_IP, CLIENT_IP, SIP_PORT, client_port, response_body)
            _ = sock.sendto(request, (SERVER_IP, SIP_PORT))
            time.sleep(0.005)
            _ = sock.sendto(response, (CLIENT_IP, client_port))
            time.sleep(0.005)
    finally:
        sock.close()
