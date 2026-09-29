# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: NFS AUTH_SYS Root UID Access
# RTA: network_nfs_auth_sys_root_uid_access.py
# Description: Emits a complete NFSv3 GETATTR RPC transaction over TCP whose
#              AUTH_SYS credential asserts UID and GID 0. Each RPC message is
#              prefixed with a final-fragment TCP RPC record marker so
#              Packetbeat's NFS parser can decode the request and reply.
#
#              Requires CAP_NET_RAW. The TCP flow is fully spoofed, so no NFS
#              server or mount is required.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

NFS_PORT = 2049
SPOOFED_CLIENT_IP = "10.20.30.40"
SPOOFED_SERVER_IP = "10.10.10.10"

_TCP_RST = 0x04
_TCP_SYN = 0x02
_TCP_SYNACK = 0x12
_TCP_PSHACK = 0x18

_RPC_CALL = 0
_RPC_REPLY = 1
_RPC_VERSION = 2
_NFS_PROGRAM = 100003
_NFS_V3 = 3
_NFS_GETATTR = 1
_AUTH_NONE = 0
_AUTH_SYS = 1
_NFS3ERR_STALE = 70


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = sum((data[offset] << 8) | data[offset + 1] for offset in range(0, len(data), 2))
    value = (value & 0xFFFF) + (value >> 16)
    value += value >> 16
    return ~value & 0xFFFF


def _xdr_opaque(value: bytes) -> bytes:
    padding = b"\x00" * ((4 - len(value) % 4) % 4)
    return struct.pack("!I", len(value)) + value + padding


def _rpc_record(rpc: bytes) -> bytes:
    """Prefix one complete RPC message with a final-fragment record marker."""
    return struct.pack("!I", 0x80000000 | len(rpc)) + rpc


def _auth_sys_root() -> bytes:
    body = struct.pack("!I", int(time.time()))
    body += _xdr_opaque(b"rta-client")
    body += struct.pack("!III", 0, 0, 0)  # UID 0, GID 0, no auxiliary groups
    return struct.pack("!II", _AUTH_SYS, len(body)) + body


def _nfs_getattr_call(xid: int) -> bytes:
    rpc = struct.pack(
        "!IIIIII",
        xid,
        _RPC_CALL,
        _RPC_VERSION,
        _NFS_PROGRAM,
        _NFS_V3,
        _NFS_GETATTR,
    )
    rpc += _auth_sys_root()
    rpc += struct.pack("!II", _AUTH_NONE, 0)
    rpc += _xdr_opaque(b"\x42" * 32)
    return rpc


def _nfs_getattr_reply(xid: int) -> bytes:
    # RPC accepted + successful dispatch, followed by an NFS stale-filehandle
    # status. The NFS error keeps the reply small while completing the event.
    return struct.pack(
        "!IIIIIII",
        xid,
        _RPC_REPLY,
        0,
        _AUTH_NONE,
        0,
        0,
        _NFS3ERR_STALE,
    )


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
    id="48bbf8e7-5af8-4f78-bd82-6a798889f66a",
    name="network_nfs_auth_sys_root_uid_access",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="35ef761a-7136-4cb9-a32d-4e7abddb3bac",
            name="NFS AUTH_SYS Root UID Access",
        )
    ],
    techniques=["T1039", "T1213"],
)
def main() -> None:
    """Emit an NFSv3 GETATTR transaction over TCP carrying AUTH_SYS UID 0."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    xid = random.randint(0x10000000, 0xEFFFFFFF)
    client_port = random.randint(32768, 60000)
    client_isn = random.randint(0x10000000, 0x6FFFFFFF)
    server_isn = random.randint(0x10000000, 0x6FFFFFFF)
    request = _rpc_record(_nfs_getattr_call(xid))
    reply = _rpc_record(_nfs_getattr_reply(xid))

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
        "Emitting NFSv3 AUTH_SYS UID 0 GETATTR over TCP: %s -> %s:%d",
        SPOOFED_CLIENT_IP,
        SPOOFED_SERVER_IP,
        NFS_PORT,
    )
    try:
        send(SPOOFED_CLIENT_IP, SPOOFED_SERVER_IP, client_port, NFS_PORT, _TCP_SYN, client_isn, 0)
        time.sleep(0.02)
        send(
            SPOOFED_SERVER_IP,
            SPOOFED_CLIENT_IP,
            NFS_PORT,
            client_port,
            _TCP_SYNACK,
            server_isn,
            client_isn + 1,
        )
        time.sleep(0.02)
        send(
            SPOOFED_CLIENT_IP,
            SPOOFED_SERVER_IP,
            client_port,
            NFS_PORT,
            _TCP_PSHACK,
            client_isn + 1,
            server_isn + 1,
            request,
        )
        time.sleep(0.05)
        send(
            SPOOFED_SERVER_IP,
            SPOOFED_CLIENT_IP,
            NFS_PORT,
            client_port,
            _TCP_PSHACK,
            server_isn + 1,
            client_isn + 1 + len(request),
            reply,
        )
        time.sleep(0.02)
        send(
            SPOOFED_CLIENT_IP,
            SPOOFED_SERVER_IP,
            client_port,
            NFS_PORT,
            _TCP_RST,
            client_isn + 1 + len(request),
            server_isn + 1 + len(reply),
        )
    finally:
        sock.close()
