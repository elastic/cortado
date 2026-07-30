# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential NFS Destructive Operation Burst
# RTA: network_nfs_destructive_operation_burst.py
# Description: Emits 80 successful NFSv3 WRITE transactions followed by 20
#              successful REMOVE transactions over one TCP connection. Every
#              RPC request and reply has a final-fragment TCP record marker,
#              satisfying the rule's volume, write, destructive-operation, and
#              NFS_OK requirements inside one minute.
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
WRITE_OPERATION_COUNT = 80
REMOVE_OPERATION_COUNT = 20
SPOOFED_CLIENT_IP = "10.20.30.40"
SPOOFED_SERVER_IP = "10.10.10.10"

_TCP_RST = 0x04
_TCP_SYN = 0x02
_TCP_SYNACK = 0x12
_TCP_PSHACK = 0x18

_RPC_CALL = 0
_RPC_REPLY = 1
_RPC_VERSION = 2
_RPC_ACCEPTED = 0
_RPC_SUCCESS = 0
_AUTH_NONE = 0
_AUTH_SYS = 1

_NFS_PROGRAM = 100003
_NFS_V3 = 3
_NFS_WRITE = 7
_NFS_REMOVE = 12
_NFS_OK = 0
_FILE_SYNC = 2

_FILE_HANDLE = b"\x42" * 32
_WRITE_DATA = b"RTA-NFS-WRITE"


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
    return struct.pack("!II", _AUTH_SYS, len(body)) + body


def _rpc_call(xid: int, procedure: int) -> bytes:
    rpc = struct.pack(
        "!IIIIII",
        xid,
        _RPC_CALL,
        _RPC_VERSION,
        _NFS_PROGRAM,
        _NFS_V3,
        procedure,
    )
    rpc += _auth_sys()
    rpc += struct.pack("!II", _AUTH_NONE, 0)
    return rpc


def _rpc_success_reply(xid: int) -> bytes:
    return struct.pack(
        "!IIIIII",
        xid,
        _RPC_REPLY,
        _RPC_ACCEPTED,
        _AUTH_NONE,
        0,
        _RPC_SUCCESS,
    )


def _write_call(xid: int, offset: int) -> bytes:
    rpc = _rpc_call(xid, _NFS_WRITE)
    rpc += _opaque(_FILE_HANDLE)
    rpc += struct.pack("!QII", offset, len(_WRITE_DATA), 0)
    rpc += _opaque(_WRITE_DATA)
    return rpc


def _write_success_reply(xid: int) -> bytes:
    rpc = _rpc_success_reply(xid)
    rpc += struct.pack("!III", _NFS_OK, 0, 0)  # status + absent pre/post operation attributes
    rpc += struct.pack("!II8s", len(_WRITE_DATA), _FILE_SYNC, b"CORTADOR")
    return rpc


def _remove_call(xid: int, index: int) -> bytes:
    rpc = _rpc_call(xid, _NFS_REMOVE)
    rpc += _opaque(_FILE_HANDLE)
    rpc += _opaque(f"encrypted-{index:04d}.rta".encode())
    return rpc


def _remove_success_reply(xid: int) -> bytes:
    rpc = _rpc_success_reply(xid)
    rpc += struct.pack("!III", _NFS_OK, 0, 0)  # status + absent directory pre/post attributes
    return rpc


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
    name="network_nfs_destructive_operation_burst",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="8e78b1a5-9674-4a96-8ce7-76ef54566a85",
            name="Potential NFS Destructive Operation Burst",
        )
    ],
    techniques=["T1486"],
)
def main() -> None:
    """Emit 80 successful WRITEs and 20 successful REMOVEs over one TCP connection."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    client_port = random.randint(32768, 60000)
    first_xid = random.randint(0x10000000, 0xDFFFFF00)
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

    def transact(request: bytes, reply: bytes) -> None:
        nonlocal client_sequence, server_sequence
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

    log.info(
        "Emitting %d successful NFSv3 WRITEs and %d REMOVEs over TCP: %s -> %s:%d",
        WRITE_OPERATION_COUNT,
        REMOVE_OPERATION_COUNT,
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

        for index in range(WRITE_OPERATION_COUNT):
            xid = first_xid + index
            transact(
                _rpc_record(_write_call(xid, index * 4096)),
                _rpc_record(_write_success_reply(xid)),
            )

        for index in range(REMOVE_OPERATION_COUNT):
            xid = first_xid + WRITE_OPERATION_COUNT + index
            transact(
                _rpc_record(_remove_call(xid, index)),
                _rpc_record(_remove_success_reply(xid)),
            )

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
