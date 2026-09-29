# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Time Seen Memcached Writer
# RTA: network_first_time_seen_memcached_writer.py
# Description: Crafts a complete TCP transaction containing a successful
#              Memcached text-protocol SET operation. A randomized private
#              client address gives each run a new client/server pair for the
#              rule's seven-day new-terms history window.
#
#              Requires CAP_NET_RAW. The request and response are spoofed, so
#              no Memcached server is required and no cached data is modified.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

MEMCACHED_PORT = 11211
SERVER_IP = "10.10.10.10"

_TCP_RST = 0x04
_TCP_SYN = 0x02
_TCP_SYNACK = 0x12
_TCP_PSHACK = 0x18

_SET_REQUEST = b"set rta.session 0 300 10\r\nrta-value!\r\n"
_STORED_RESPONSE = b"STORED\r\n"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = sum((data[index] << 8) | data[index + 1] for index in range(0, len(data), 2))
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


@register_code_rta(
    id="3a9a994e-64db-4b77-8b64-1b4436db1a7d",
    name="network_first_time_seen_memcached_writer",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="63c3c736-72e1-4d41-8022-27b5c4935e93",
            name="First Time Seen Memcached Writer",
        )
    ],
    techniques=["T1565.001"],
)
def main() -> None:
    """Emit a successful Memcached SET from a randomized client address."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_ip = f"10.200.{random.randint(1, 254)}.{random.randint(1, 254)}"
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
        "Emitting successful Memcached SET from new client %s to %s:%d",
        client_ip,
        SERVER_IP,
        MEMCACHED_PORT,
    )
    try:
        send(client_ip, SERVER_IP, client_port, MEMCACHED_PORT, _TCP_SYN, client_isn, 0)
        time.sleep(0.02)
        send(
            SERVER_IP,
            client_ip,
            MEMCACHED_PORT,
            client_port,
            _TCP_SYNACK,
            server_isn,
            client_isn + 1,
        )
        time.sleep(0.02)
        send(
            client_ip,
            SERVER_IP,
            client_port,
            MEMCACHED_PORT,
            _TCP_PSHACK,
            client_isn + 1,
            server_isn + 1,
            _SET_REQUEST,
        )
        time.sleep(0.05)
        send(
            SERVER_IP,
            client_ip,
            MEMCACHED_PORT,
            client_port,
            _TCP_PSHACK,
            server_isn + 1,
            client_isn + 1 + len(_SET_REQUEST),
            _STORED_RESPONSE,
        )
        time.sleep(0.02)
        send(
            client_ip,
            SERVER_IP,
            client_port,
            MEMCACHED_PORT,
            _TCP_RST,
            client_isn + 1 + len(_SET_REQUEST),
            server_isn + 1 + len(_STORED_RESPONSE),
        )
    finally:
        sock.close()
