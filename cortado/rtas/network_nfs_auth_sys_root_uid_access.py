# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: NFS AUTH_SYS Root UID Access
# RTA: network_nfs_auth_sys_root_uid_access.py
# Description: Emits a complete NFSv3 GETATTR RPC transaction whose AUTH_SYS
#              credential asserts UID and GID 0. The request and reply are raw
#              UDP packets with reversed endpoints so Network Packet Capture
#              decodes one NFS transaction and populates the RPC credential
#              fields used by the rule.
#
#              Requires CAP_NET_RAW. Both directions are emitted through the
#              physical interface; no NFS server or mount is required.

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

_RPC_CALL = 0
_RPC_REPLY = 1
_RPC_VERSION = 2
_NFS_PROGRAM = 100003
_NFS_V3 = 3
_NFS_GETATTR = 1
_AUTH_NONE = 0
_AUTH_SYS = 1
_NFS3ERR_STALE = 70


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    value = 0
    for offset in range(0, len(data), 2):
        value += (data[offset] << 8) | data[offset + 1]
    value = (value & 0xFFFF) + (value >> 16)
    value += value >> 16
    return ~value & 0xFFFF


def _xdr_opaque(value: bytes) -> bytes:
    padding = b"\x00" * ((4 - len(value) % 4) % 4)
    return struct.pack("!I", len(value)) + value + padding


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


def _raw_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    udp_length = 8 + len(payload)

    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_UDP, udp_length)
    udp_without_checksum = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    udp_checksum = _ones_complement_sum(pseudo + udp_without_checksum + payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    total_length = 20 + udp_length
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        random.randint(0, 0xFFFF),
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        src_bytes,
        dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_without_checksum)
    ip_header = ip_without_checksum[:10] + struct.pack("!H", ip_checksum) + ip_without_checksum[12:]
    return ip_header + udp_header + payload


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
    """Emit an NFSv3 GETATTR transaction carrying AUTH_SYS UID 0."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    xid = random.randint(0x10000000, 0xEFFFFFFF)
    client_port = random.randint(32768, 60000)
    request = _raw_udp_packet(
        SPOOFED_CLIENT_IP,
        SPOOFED_SERVER_IP,
        client_port,
        NFS_PORT,
        _nfs_getattr_call(xid),
    )
    reply = _raw_udp_packet(
        SPOOFED_SERVER_IP,
        SPOOFED_CLIENT_IP,
        NFS_PORT,
        client_port,
        _nfs_getattr_reply(xid),
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        log.info(
            "Emitting NFSv3 AUTH_SYS UID 0 GETATTR transaction: %s -> %s:%d",
            SPOOFED_CLIENT_IP,
            SPOOFED_SERVER_IP,
            NFS_PORT,
        )
        _ = sock.sendto(request, (SPOOFED_SERVER_IP, NFS_PORT))
        time.sleep(0.05)
        _ = sock.sendto(reply, (SPOOFED_CLIENT_IP, client_port))
    finally:
        sock.close()
