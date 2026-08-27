# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Thrift RPC Method from an External Client
# RTA: network_thrift_rpc_method_from_external_client.py
# Description: Crafts a complete TCP transaction carrying a strict TBinary
#              Apache Thrift call and reply. The client address is public and
#              the server address is private, causing Network Packet Capture to
#              populate an external client, server, and decoded Thrift method.
#
#              Requires CAP_NET_RAW. The flow is fully spoofed and does not
#              connect to a live Thrift service.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

THRIFT_PORT = 9090
PUBLIC_CLIENT_IP = "9.9.9.9"
PRIVATE_SERVER_IP = "10.10.10.10"

_TCP_RST = 0x04
_TCP_SYN = 0x02
_TCP_SYNACK = 0x12
_TCP_PSHACK = 0x18

_THRIFT_VERSION_1 = 0x80010000
_THRIFT_CALL = 1
_THRIFT_REPLY = 2
_METHOD = b"getServerStatus"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    value = (value & 0xFFFF) + (value >> 16)
    value += value >> 16
    return ~value & 0xFFFF


def _tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int,
    sequence: int,
    acknowledgement: int,
    payload: bytes = b"",
) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp_length = 20 + len(payload)
    tcp_zero = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, socket.IPPROTO_TCP, tcp_length)
    tcp_checksum = _checksum(pseudo + tcp_zero + payload)
    tcp = tcp_zero[:16] + struct.pack("!H", tcp_checksum) + tcp_zero[18:]

    ip_zero = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + tcp_length,
        random.randint(0, 0xFFFF),
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        src,
        dst,
    )
    ip = ip_zero[:10] + struct.pack("!H", _checksum(ip_zero)) + ip_zero[12:]
    return ip + tcp + payload


def _thrift_message(message_type: int) -> bytes:
    # Strict TBinary message header followed by an empty argument/result struct.
    return (
        struct.pack("!I", _THRIFT_VERSION_1 | message_type)
        + struct.pack("!I", len(_METHOD))
        + _METHOD
        + struct.pack("!I", 1)
        + b"\x00"
    )


@register_code_rta(
    id="7662771d-8645-445a-876f-96cc011a9be1",
    name="network_thrift_rpc_method_from_external_client",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="3b15d24d-03e8-422c-b260-e0834e5fec83",
            name="Thrift RPC Method from an External Client",
        )
    ],
    techniques=["T1190"],
)
def main() -> None:
    """Emit one decoded Thrift call from a public client to a private server."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    request = _thrift_message(_THRIFT_CALL)
    response = _thrift_message(_THRIFT_REPLY)
    client_port = random.randint(32768, 60000)
    client_isn = random.randint(0x10000000, 0x6FFFFFFF)
    server_isn = random.randint(0x10000000, 0x6FFFFFFF)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: int,
        sequence: int,
        acknowledgement: int,
        payload: bytes = b"",
    ) -> None:
        packet = _tcp_packet(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flags,
            sequence,
            acknowledgement,
            payload,
        )
        _ = sock.sendto(packet, (dst_ip, dst_port))

    log.info(
        "Emitting Thrift method %s from public client %s to %s:%d",
        _METHOD.decode(),
        PUBLIC_CLIENT_IP,
        PRIVATE_SERVER_IP,
        THRIFT_PORT,
    )
    try:
        send(PUBLIC_CLIENT_IP, PRIVATE_SERVER_IP, client_port, THRIFT_PORT, _TCP_SYN, client_isn, 0)
        time.sleep(0.02)
        send(
            PRIVATE_SERVER_IP,
            PUBLIC_CLIENT_IP,
            THRIFT_PORT,
            client_port,
            _TCP_SYNACK,
            server_isn,
            client_isn + 1,
        )
        time.sleep(0.02)
        send(
            PUBLIC_CLIENT_IP,
            PRIVATE_SERVER_IP,
            client_port,
            THRIFT_PORT,
            _TCP_PSHACK,
            client_isn + 1,
            server_isn + 1,
            request,
        )
        time.sleep(0.05)
        send(
            PRIVATE_SERVER_IP,
            PUBLIC_CLIENT_IP,
            THRIFT_PORT,
            client_port,
            _TCP_PSHACK,
            server_isn + 1,
            client_isn + 1 + len(request),
            response,
        )
        time.sleep(0.02)
        send(
            PUBLIC_CLIENT_IP,
            PRIVATE_SERVER_IP,
            client_port,
            THRIFT_PORT,
            _TCP_RST,
            client_isn + 1 + len(request),
            server_isn + 1 + len(response),
        )
    finally:
        sock.close()
