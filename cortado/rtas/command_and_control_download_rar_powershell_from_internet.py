# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Roshal Archive (RAR) or PowerShell File Downloaded from the Internet
# RTA: command_and_control_download_rar_powershell_from_internet.py
# Description: Forges a complete bidirectional HTTP/1.1 transaction on the wire
#              from an internal (RFC1918) source to a public destination. The
#              request downloads "/elastic-rta-payload.rar", causing the HTTP
#              parser to populate url.path and url.extension with values matched
#              by the detection rule.
#
#              Both directions are forged so Packetbeat / the network_traffic
#              integration can reassemble the request and response into a
#              logs-network_traffic.http-* event. A local HTTP server cannot be
#              used because the rule excludes private and special-purpose
#              destination addresses.
#
#              Flow: SYN -> SYN/ACK -> ACK -> client GET payload.rar ->
#              server HTTP/1.1 200 -> FIN/ACK exchange.
#
#              Requires CAP_NET_RAW (run as root or with the capability set).
#              The local kernel holds no TCP state for the forged conversation;
#              replies to the forged endpoints go nowhere, which is expected.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

HTTP_PORT = 80
INTERNAL_SOURCE_IP = "10.10.10.22"
PUBLIC_DESTINATION_IP = "8.8.8.8"
DOWNLOAD_PATH = "/elastic-rta-payload.rar"

RAR_PAYLOAD = b"Rar!\x1a\x07\x01\x00"
HTTP_REQUEST = (
    f"GET {DOWNLOAD_PATH} HTTP/1.1\r\n"
    f"Host: {PUBLIC_DESTINATION_IP}\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode("ascii")
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/vnd.rar\r\n"
    b"Content-Length: " + str(len(RAR_PAYLOAD)).encode("ascii") + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    + RAR_PAYLOAD
)

_TCP_SYN = 0x02
_TCP_ACK = 0x10
_TCP_FIN = 0x01
_TCP_SYNACK = _TCP_SYN | _TCP_ACK
_TCP_PSHACK = 0x18
_TCP_FINACK = _TCP_FIN | _TCP_ACK


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return ~total & 0xFFFF


def _build_raw_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    tcp_flags: int,
    seq: int,
    ack_seq: int,
    payload: bytes = b"",
) -> bytes:
    """Build a complete raw IPv4/TCP packet with an optional payload."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    data_offset = 5 << 4
    tcp_length = 20 + len(payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        data_offset,
        tcp_flags,
        8192,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_bytes,
        dst_bytes,
        0,
        socket.IPPROTO_TCP,
        tcp_length,
    )
    tcp_checksum = _ones_complement_sum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        data_offset,
        tcp_flags,
        8192,
        tcp_checksum,
        0,
    )

    ip_total_length = 20 + tcp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_length,
        random.randint(0, 0xFFFF),
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        src_bytes,
        dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]

    return ip_header + tcp_header + payload


@register_code_rta(
    id="7006c5f8-7f32-4b31-8613-b34f20dc8ece",
    name="command_and_control_download_rar_powershell_from_internet",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="ff013cb4-274d-434a-96bb-fe15ddd3ae92",
            name="Roshal Archive (RAR) or PowerShell File Downloaded from the Internet",
        )
    ],
    techniques=["T1105"],
)
def main() -> None:
    """Forge an internal-to-public HTTP transaction that downloads a RAR file."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    source_port = random.randint(32768, 60000)
    client_isn = random.randint(0x10000000, 0x7FFFFFFF)
    server_isn = random.randint(0x10000000, 0x7FFFFFFF)

    def client(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            INTERNAL_SOURCE_IP,
            PUBLIC_DESTINATION_IP,
            source_port,
            HTTP_PORT,
            flags,
            seq,
            ack,
            payload,
        )

    def server(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            PUBLIC_DESTINATION_IP,
            INTERNAL_SOURCE_IP,
            HTTP_PORT,
            source_port,
            flags,
            seq,
            ack,
            payload,
        )

    client_seq = client_isn + 1
    server_seq = server_isn + 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    log.info(
        "Forging HTTP RAR download %s:%d -> %s:%d%s",
        INTERNAL_SOURCE_IP,
        source_port,
        PUBLIC_DESTINATION_IP,
        HTTP_PORT,
        DOWNLOAD_PATH,
    )
    try:
        _ = sock.sendto(client(_TCP_SYN, client_isn, 0), (PUBLIC_DESTINATION_IP, HTTP_PORT))
        time.sleep(0.02)
        _ = sock.sendto(server(_TCP_SYNACK, server_isn, client_isn + 1), (INTERNAL_SOURCE_IP, source_port))
        time.sleep(0.02)
        _ = sock.sendto(client(_TCP_ACK, client_seq, server_seq), (PUBLIC_DESTINATION_IP, HTTP_PORT))

        _ = sock.sendto(
            client(_TCP_PSHACK, client_seq, server_seq, HTTP_REQUEST),
            (PUBLIC_DESTINATION_IP, HTTP_PORT),
        )
        client_seq += len(HTTP_REQUEST)
        time.sleep(0.02)
        _ = sock.sendto(
            server(_TCP_PSHACK, server_seq, client_seq, HTTP_RESPONSE),
            (INTERNAL_SOURCE_IP, source_port),
        )
        server_seq += len(HTTP_RESPONSE)
        time.sleep(0.02)

        _ = sock.sendto(client(_TCP_FINACK, client_seq, server_seq), (PUBLIC_DESTINATION_IP, HTTP_PORT))
        _ = sock.sendto(server(_TCP_FINACK, server_seq, client_seq + 1), (INTERNAL_SOURCE_IP, source_port))
        _ = sock.sendto(client(_TCP_ACK, client_seq + 1, server_seq + 1), (PUBLIC_DESTINATION_IP, HTTP_PORT))
        log.info("Forged RAR download transaction emitted")
    except OSError as e:
        log.error("Failed to send forged HTTP transaction: %s", e)
    finally:
        sock.close()
