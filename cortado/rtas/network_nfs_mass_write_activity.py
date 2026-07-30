# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential NFS Mass Write Activity
# RTA: network_nfs_mass_write_activity.py
# Description: Emits 100 complete NFSv3 WRITE RPC transactions over one TCP
#              connection. Each request and reply uses a TCP RPC record marker
#              and a unique transaction ID, causing Network Packet Capture to
#              publish 100 WRITE events inside one minute.
#
#              Requires CAP_NET_RAW. The TCP flow is fully spoofed, so no NFS
#              server, exported share, or file modification is required.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

NFS_PORT = 2049
MUTATING_OPERATION_COUNT = 100
SPOOFED_CLIENT_IP = "10.20.30.40"
SPOOFED_SERVER_IP = "10.10.10.10"

_TCP_RST = 0x04
_TCP_SYN = 0x02
_TCP_SYNACK = 0x12
_TCP_PSHACK = 0x18

_NFS_PROGRAM = 100003
_NFS_V3 = 3
_NFS_WRITE = 7
_NFS3ERR_STALE = 70


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = sum((data[offset] << 8) | data[offset + 1] for offset in range(0, len(data), 2))
    value = (value & 0xFFFF) + (value >> 16)
    value += value >> 16
    return ~value & 0xFFFF


def _opaque(value: bytes) -> bytes:
    return struct.pack("!I", len(value)) + value + b"\x00" * ((4 - len(value) % 4) % 4)


def _rpc_record(rpc: bytes) -> bytes:
    """Prefix one complete RPC message with a final-fragment record marker."""
    return struct.pack("!I", 0x80000000 | len(rpc)) + rpc


def _auth_sys() -> bytes:
    body = struct.pack("!I", int(time.time()))
    body += _opaque(b"rta-client")
    body += struct.pack("!III", 1000, 1000, 0)
    return struct.pack("!II", 1, len(body)) + body


def _write_call(xid: int, offset: int) -> bytes:
    rpc = struct.pack("!IIIIII", xid, 0, 2, _NFS_PROGRAM, _NFS_V3, _NFS_WRITE)
    rpc += _auth_sys()
    rpc += struct.pack("!II", 0, 0)
    rpc += _opaque(b"\x42" * 32)
    data = b"RTA-NFS-WRITE"
    rpc += struct.pack("!QII", offset, len(data), 0)
    rpc += _opaque(data)
    return rpc


def _error_reply(xid: int) -> bytes:
    return struct.pack("!IIIIIII", xid, 1, 0, 0, 0, 0, _NFS3ERR_STALE)


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
    id="55fedc1c-5dcb-4f03-ae2a-66477d293648",
    name="network_nfs_mass_write_activity",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="8e78b1a5-9674-4a96-8ce7-76ef54566a85",
            name="Potential NFS Mass Write Activity",
        )
    ],
    techniques=["T1486"],
)
def main() -> None:
    """Emit 100 NFSv3 WRITE transactions over one TCP connection."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_port = random.randint(32768, 60000)
    first_xid = random.randint(0x10000000, 0xDFFFFFFF)
    client_sequence = random.randint(0x10000000, 0x4FFFFFFF)
    server_sequence = random.randint(0x10000000, 0x4FFFFFFF)
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
        "Emitting %d NFSv3 WRITE transactions over TCP: %s -> %s:%d",
        MUTATING_OPERATION_COUNT,
        SPOOFED_CLIENT_IP,
        SPOOFED_SERVER_IP,
        NFS_PORT,
    )
    try:
        send(
            SPOOFED_CLIENT_IP,
            SPOOFED_SERVER_IP,
            client_port,
            NFS_PORT,
            _TCP_SYN,
            client_sequence,
            0,
        )
        time.sleep(0.02)
        send(
            SPOOFED_SERVER_IP,
            SPOOFED_CLIENT_IP,
            NFS_PORT,
            client_port,
            _TCP_SYNACK,
            server_sequence,
            client_sequence + 1,
        )
        time.sleep(0.02)
        client_sequence += 1
        server_sequence += 1

        for index in range(MUTATING_OPERATION_COUNT):
            xid = first_xid + index
            request = _rpc_record(_write_call(xid, index * 4096))
            reply = _rpc_record(_error_reply(xid))
            send(
                SPOOFED_CLIENT_IP,
                SPOOFED_SERVER_IP,
                client_port,
                NFS_PORT,
                _TCP_PSHACK,
                client_sequence,
                server_sequence,
                request,
            )
            client_sequence += len(request)
            time.sleep(0.002)
            send(
                SPOOFED_SERVER_IP,
                SPOOFED_CLIENT_IP,
                NFS_PORT,
                client_port,
                _TCP_PSHACK,
                server_sequence,
                client_sequence,
                reply,
            )
            server_sequence += len(reply)
            time.sleep(0.002)

        send(
            SPOOFED_CLIENT_IP,
            SPOOFED_SERVER_IP,
            client_port,
            NFS_PORT,
            _TCP_RST,
            client_sequence,
            server_sequence,
        )
    finally:
        sock.close()
