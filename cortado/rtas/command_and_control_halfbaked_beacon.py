# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Halfbaked Command and Control Beacon
# RTA: command_and_control_halfbaked_beacon.py
# Description: Forges a complete bidirectional HTTP/1.1 transaction on the wire
#              whose request line and Host header reconstruct to the Halfbaked
#              beacon URL the rule keys on: url.full RLIKE http://<ip>/cd . The
#              rule's RLIKE is anchored (full-string), so url.full must be exactly
#              "http://<ip>/cd" with no port suffix - which means the transaction
#              must use TCP/80 (the default HTTP port, omitted from url.full) and
#              request path exactly "/cd" with an IP-literal Host header.
#
#              Both directions are forged as raw IP/TCP packets to a NON-LOCAL,
#              documentation-range destination (TEST-NET-3, 203.0.113.0/24) so the
#              packets egress the physical NIC where the sensor (Packetbeat /
#              network_traffic HTTP parser) captures them and reassembles a full
#              request+response transaction into logs-network_traffic.http-*.
#
#              Flow: SYN -> SYN/ACK -> ACK -> client GET /cd (Host: <ip>) ->
#              server HTTP/1.1 200 -> FIN/ACK exchange. The reassembled event
#              carries url.full=http://<ip>/cd, destination.port=80,
#              network.protocol=http and network.transport=tcp - satisfying every
#              clause of the detection rule.
#
#              Requires CAP_NET_RAW (run as root or with the capability set). The
#              local kernel holds no TCP state for the forged conversation; replies
#              to the forged endpoints go nowhere, which is expected.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

HTTP_PORT = 80  # default HTTP port -> omitted from url.full, so url.full == http://<ip>/cd
VICTIM_SOURCE_IP = "10.10.10.22"     # the beaconing (compromised) host
C2_DEST_IP = "203.0.113.30"          # the Halfbaked C2 server (IP-literal Host)

# GET /cd with an IP-literal Host reconstructs to url.full = http://203.0.113.30/cd,
# which the rule matches with http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/cd
HTTP_REQUEST = (
    f"GET /cd HTTP/1.1\r\n"
    f"Host: {C2_DEST_IP}\r\n"
    f"User-Agent: Mozilla/4.0 (compatible; MSIE 8.0)\r\n"
    f"Connection: close\r\n"
    f"\r\n"
).encode("ascii")

HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

_TCP_SYN = 0x02
_TCP_ACK = 0x10
_TCP_FIN = 0x01
_TCP_SYNACK = _TCP_SYN | _TCP_ACK
_TCP_PSHACK = 0x18  # PSH | ACK
_TCP_FINACK = _TCP_FIN | _TCP_ACK


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


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
    """Build a complete raw IP/TCP packet with optional application payload."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    data_offset = 5 << 4  # 20-byte TCP header, no options
    tcp_seg_len = 20 + len(payload)

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq, data_offset, tcp_flags, 8192, 0, 0,
    )
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_TCP, tcp_seg_len)
    tcp_checksum = _ones_complement_sum(pseudo + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq, data_offset, tcp_flags, 8192, tcp_checksum, 0,
    )

    ip_total_len = 20 + 20 + len(payload)
    ident = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_TCP, 0, src_bytes, dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_TCP, ip_checksum, src_bytes, dst_bytes,
    )

    return ip_header + tcp_header + payload


@register_code_rta(
    id="1075eabb-7b4e-4f11-b7cc-10b68e33d755",
    name="command_and_control_halfbaked_beacon",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="2e580225-2a58-48ef-938b-572933be06fe",
            name="Halfbaked Command and Control Beacon",
        )
    ],
    techniques=["T1071", "T1071.001", "T1568", "T1568.002"],
)
def main() -> None:
    """Forge a full HTTP GET /cd transaction to TCP/80 so url.full == http://<ip>/cd."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    src_port = random.randint(32768, 60000)
    c_isn = random.randint(0x10000000, 0x7FFFFFFF)
    s_isn = random.randint(0x10000000, 0x7FFFFFFF)

    def client(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(VICTIM_SOURCE_IP, C2_DEST_IP, src_port, HTTP_PORT, flags, seq, ack, payload)

    def server(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(C2_DEST_IP, VICTIM_SOURCE_IP, HTTP_PORT, src_port, flags, seq, ack, payload)

    c_seq = c_isn + 1   # after SYN consumes one sequence number
    s_seq = s_isn + 1   # after SYN/ACK consumes one sequence number

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    log.info(
        "Forging HTTP GET /cd %s -> %s:%d (Halfbaked C2 beacon emulation, url.full=http://%s/cd)",
        VICTIM_SOURCE_IP, C2_DEST_IP, HTTP_PORT, C2_DEST_IP,
    )
    try:
        # --- TCP three-way handshake ---
        _ = sock.sendto(client(_TCP_SYN, c_isn, 0), (C2_DEST_IP, HTTP_PORT))
        time.sleep(0.02)
        _ = sock.sendto(server(_TCP_SYNACK, s_isn, c_isn + 1), (VICTIM_SOURCE_IP, src_port))
        time.sleep(0.02)
        _ = sock.sendto(client(_TCP_ACK, c_seq, s_seq), (C2_DEST_IP, HTTP_PORT))

        # --- HTTP request / response ---
        _ = sock.sendto(client(_TCP_PSHACK, c_seq, s_seq, HTTP_REQUEST), (C2_DEST_IP, HTTP_PORT))
        c_seq += len(HTTP_REQUEST)
        time.sleep(0.02)
        _ = sock.sendto(server(_TCP_PSHACK, s_seq, c_seq, HTTP_RESPONSE), (VICTIM_SOURCE_IP, src_port))
        s_seq += len(HTTP_RESPONSE)
        time.sleep(0.02)

        # --- graceful close so the sensor emits the completed HTTP event ---
        _ = sock.sendto(client(_TCP_FINACK, c_seq, s_seq), (C2_DEST_IP, HTTP_PORT))
        _ = sock.sendto(server(_TCP_FINACK, s_seq, c_seq + 1), (VICTIM_SOURCE_IP, src_port))
        _ = sock.sendto(client(_TCP_ACK, c_seq + 1, s_seq + 1), (C2_DEST_IP, HTTP_PORT))

        log.info("Forged Halfbaked HTTP GET /cd transaction emitted")
    except OSError as e:
        log.error("Failed to send forged HTTP transaction: %s", e)
    finally:
        sock.close()
