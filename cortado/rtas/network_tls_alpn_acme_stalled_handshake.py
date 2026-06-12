# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Repeated Stalled TLS Handshakes via ALPN acme-tls/1 Extension
# RTA: network_tls_alpn_acme_stalled_handshake.py
# Description: Emulates the CVE-2026-22045 goroutine-exhaustion DoS pattern by
#              sending THRESHOLD_COUNT raw IP/TCP flows, each carrying a manually
#              crafted TLS ClientHello that advertises acme-tls/1 as its sole ALPN
#              extension. Flows are spoofed (src = SPOOFED_SOURCE_IP) and aimed at
#              a non-local destination (PRIVATE_DESTINATION_IP) so the packets
#              egress through the physical NIC where Packetbeat captures.
#
#              Each flow is three raw packets:
#                1. TCP SYN   — opens the Packetbeat flow
#                2. TCP PSH+ACK + TLS ClientHello (acme-tls/1 ALPN)
#                3. TCP RST   — closes the flow after STALL_SECONDS
#
#              Packetbeat / network_traffic with TLS parsing and
#              include_detailed_fields: true sees each connection as:
#                - tls.detailed.client_hello.extensions
#                    .application_layer_protocol_negotiation = "acme-tls/1"
#                - tls.established = false  (no ServerHello on the wire)
#                - network.bytes < 1024     (TLS ClientHello payload only ~80 B)
#                - event.duration >= 10000000000  (12 s between SYN and RST)
#
#              Five such events from the same source.ip + destination.ip pair
#              fire the threshold rule. All flows run in parallel so total
#              wall time is approximately STALL_SECONDS.
#
#              The local-server pattern cannot be used here because connecting
#              to get_host_ip() from the same host routes through the loopback
#              interface (lo), which Packetbeat does not capture. Raw sockets
#              with a non-local destination are required to hit the physical NIC.
#
#              Requires CAP_NET_RAW (run as root or with capability set).

import logging
import os
import random
import socket
import struct
import threading
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

TLS_PORT = 8443
STALL_SECONDS = 12          # SYN→RST gap; must exceed the rule's 10 s floor
THRESHOLD_COUNT = 5         # matches the rule's threshold value

# Source IP is spoofed so gateway RST/ICMP replies go to a non-existent host
# and never reach our kernel's TCP stack.
SPOOFED_SOURCE_IP = "10.10.10.5"
# Destination is non-local; routes via the default gateway on the physical NIC.
PRIVATE_DESTINATION_IP = "10.10.10.10"

_ALPN_PROTOCOL = b"acme-tls/1"

_TCP_SYN    = 0x02
_TCP_RST    = 0x04
_TCP_PSHACK = 0x18   # PSH | ACK


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
        src_port, dst_port, seq, ack_seq,
        data_offset, tcp_flags, 8192, 0, 0,
    )
    pseudo = struct.pack(
        "!4s4sBBH",
        src_bytes, dst_bytes, 0, socket.IPPROTO_TCP, tcp_seg_len,
    )
    tcp_checksum = _ones_complement_sum(pseudo + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        data_offset, tcp_flags, 8192, tcp_checksum, 0,
    )

    ip_total_len = 20 + 20 + len(payload)
    ident = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_TCP, 0,
        src_bytes, dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, ident, 0, 64, socket.IPPROTO_TCP, ip_checksum,
        src_bytes, dst_bytes,
    )

    return ip_header + tcp_header + payload


def _build_tls_client_hello() -> bytes:
    """
    Build a minimal but well-formed TLS ClientHello with acme-tls/1 as
    the sole ALPN protocol. Uses os.urandom for the 32-byte random so
    each of the five flows looks distinct on the wire.
    """
    random_bytes = os.urandom(32)

    # Supported Versions extension — advertise TLS 1.3 and TLS 1.2
    ext_supported_versions = (
        b"\x00\x2b"     # type: supported_versions (43)
        b"\x00\x05"     # ext data length: 5
        b"\x04"         # versions list length: 4
        b"\x03\x04"     # TLS 1.3
        b"\x03\x03"     # TLS 1.2
    )

    # ALPN extension — exactly one protocol: "acme-tls/1"
    _name_len = len(_ALPN_PROTOCOL)          # 10
    _list_len = 1 + _name_len               # 11  (1-byte name length + name)
    _ext_data_len = 2 + _list_len           # 13  (2-byte list length + list)
    ext_alpn = (
        b"\x00\x10"                                     # type: ALPN (16)
        + struct.pack("!H", _ext_data_len)              # ext data length: 13
        + struct.pack("!H", _list_len)                  # ProtocolNameList length: 11
        + struct.pack("!B", _name_len)                  # ProtocolName length: 10
        + _ALPN_PROTOCOL                                # b"acme-tls/1"
    )

    extensions = ext_supported_versions + ext_alpn

    client_hello_body = (
        b"\x03\x03"                                     # ClientHello version: TLS 1.2
        + random_bytes                                   # 32-byte random
        + b"\x00"                                       # session ID length: 0
        + b"\x00\x04"                                   # cipher suites length: 4
        + b"\x13\x01"                                   # TLS_AES_128_GCM_SHA256
        + b"\x00\x2f"                                   # TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01\x00"                                   # 1 compression method: null
        + struct.pack("!H", len(extensions))            # extensions length
        + extensions
    )

    handshake = (
        b"\x01"                                         # HandshakeType: ClientHello
        + struct.pack("!I", len(client_hello_body))[1:] # 3-byte length
        + client_hello_body
    )

    return (
        b"\x16\x03\x01"                                 # TLS Handshake, record version TLS 1.0
        + struct.pack("!H", len(handshake))             # record length
        + handshake
    )


def _stalled_tls_flow(sock: socket.socket, src_port: int) -> None:
    """
    Emit one stalled TLS ClientHello flow via raw socket:
      SYN → (50 ms) → PSH+ACK+TLS ClientHello → (STALL_SECONDS) → RST
    """
    tls_hello = _build_tls_client_hello()
    isn = random.randint(0x10000000, 0x7FFFFFFF)

    # SYN — opens the Packetbeat flow entry
    pkt = _build_raw_packet(
        SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP,
        src_port, TLS_PORT,
        _TCP_SYN, isn, 0,
    )
    sock.sendto(pkt, (PRIVATE_DESTINATION_IP, TLS_PORT))
    log.debug("SYN sent from %s:%d", SPOOFED_SOURCE_IP, src_port)
    time.sleep(0.05)

    # PSH+ACK carrying the TLS ClientHello with acme-tls/1 ALPN
    pkt = _build_raw_packet(
        SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP,
        src_port, TLS_PORT,
        _TCP_PSHACK, isn + 1, 1,
        tls_hello,
    )
    sock.sendto(pkt, (PRIVATE_DESTINATION_IP, TLS_PORT))
    log.debug("TLS ClientHello (acme-tls/1) sent from %s:%d", SPOOFED_SOURCE_IP, src_port)

    # Stall — keeps the flow open so event.duration >= STALL_SECONDS
    time.sleep(STALL_SECONDS)

    # RST — closes the flow and causes Packetbeat to emit the TLS event
    pkt = _build_raw_packet(
        SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP,
        src_port, TLS_PORT,
        _TCP_RST, isn + 1 + len(tls_hello), 1,
    )
    sock.sendto(pkt, (PRIVATE_DESTINATION_IP, TLS_PORT))
    log.debug("RST sent from %s:%d (flow closed)", SPOOFED_SOURCE_IP, src_port)


@register_code_rta(
    id="2e601ae0-6f9d-4659-a7ac-5961abecc2cf",
    name="network_tls_alpn_acme_stalled_handshake",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="581bd9b4-ee08-415a-97d7-756e6c53c264",
            name="Repeated Stalled TLS Handshakes via ALPN acme-tls/1 Extension",
        )
    ],
    techniques=["T1499", "T1499.002"],
)
def main() -> None:
    """Emit 5 raw stalled TLS flows with acme-tls/1 ALPN on TCP/8443 to fire the threshold rule."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    base_port = random.randint(32768, 60000)

    log.info(
        "Sending %d stalled TLS flows (acme-tls/1 ALPN) from %s to %s:%d — stalling %ds",
        THRESHOLD_COUNT, SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, TLS_PORT, STALL_SECONDS,
    )

    threads: list[threading.Thread] = []
    for i in range(THRESHOLD_COUNT):
        t = threading.Thread(
            target=_stalled_tls_flow,
            args=(sock, base_port + i),
            daemon=True,
            name=f"acme-tls-flow-{i}",
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=STALL_SECONDS + 10)

    sock.close()
    log.info("Stalled handshake emulation complete")
