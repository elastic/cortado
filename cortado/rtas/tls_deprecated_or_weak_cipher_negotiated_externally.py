# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Deprecated TLS Version or Weak Cipher Negotiated Externally
# RTA: tls_deprecated_or_weak_cipher_negotiated_externally.py
# Description: Forges a complete bidirectional TLS 1.0 handshake on the wire
#              between an internal RFC1918 source and an external public
#              destination, negotiating a weak cipher (RC4-SHA). This emulates a
#              downgraded / weak-cipher session as captured by a network sensor
#              (Packetbeat network_traffic, Zeek, or PAN-OS) and indexed into
#              logs-network_traffic.tls-*.
#
#              Unlike a ClientHello-only emulation, this rule requires
#              tls.established:true plus a negotiated deprecated version or weak
#              cipher, which the sensor reads from the ServerHello. Both
#              directions are therefore forged as raw packets so the sensor
#              observes a full, completed handshake:
#
#                client(10.10.10.10) -> SYN              -> server(8.8.8.8:443)
#                server              -> SYN/ACK           -> client
#                client              -> ACK
#                client              -> TLS ClientHello   (offers RC4/3DES/AES, ver TLS 1.0)
#                server              -> TLS ServerHello   (selects TLS 1.0 + RC4-SHA) + ServerHelloDone
#                client              -> ChangeCipherSpec + (encrypted) Finished
#                server              -> ChangeCipherSpec + (encrypted) Finished
#                client/server       -> FIN/ACK exchange  (flow closes, event emitted)
#
#              The sensor then reports tls.version=1.0, tls.cipher containing
#              "RC4", and tls.established=true, satisfying both branches of the
#              rule. Source 10.10.10.10 is RFC1918; destination 8.8.8.8 is public.
#
#              Both endpoints are spoofed/forged, so no real listener or external
#              legacy server is needed and the negotiated parameters are fully
#              deterministic. Packets egress the physical NIC where the sensor
#              captures them.
#
#              Requires CAP_NET_RAW (run as root or with the capability set). The
#              local kernel has no TCP state for this conversation; replies to
#              the forged source go nowhere, which is expected.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

TLS_PORT = 443
INTERNAL_SOURCE_IP = "10.10.10.10"   # RFC1918 source -> satisfies the rule
EXTERNAL_DEST_IP = "8.8.8.8"         # public destination (outside excluded ranges)

# ServerHello selections that trigger the rule (covers both branches):
_TLS10_VERSION = b"\x03\x01"         # TLS 1.0 -> tls.version:1.0
_CIPHER_RC4_SHA = b"\x00\x05"        # TLS_RSA_WITH_RC4_128_SHA -> tls.cipher:*RC4*

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


def _tls_record(content_type: int, body: bytes) -> bytes:
    """Wrap a payload in a TLS record with a TLS 1.0 record-layer version."""
    return struct.pack("!BBBH", content_type, 0x03, 0x01, len(body)) + body


def _handshake(msg_type: int, body: bytes) -> bytes:
    """Build a TLS handshake message (1-byte type + 3-byte length + body)."""
    return struct.pack("!B", msg_type) + struct.pack("!I", len(body))[1:] + body


def _client_hello() -> bytes:
    """ClientHello offering legacy TLS 1.0 and weak cipher suites."""
    cipher_suites = _CIPHER_RC4_SHA + b"\x00\x0a" + b"\x00\x2f"  # RC4-SHA, 3DES-SHA, AES128-SHA
    body = (
        _TLS10_VERSION
        + os.urandom(32)            # client random
        + b"\x00"                   # session id length: 0
        + struct.pack("!H", len(cipher_suites)) + cipher_suites
        + b"\x01\x00"               # 1 compression method: null
    )
    return _tls_record(0x16, _handshake(0x01, body))


def _server_hello() -> bytes:
    """ServerHello selecting TLS 1.0 + RC4-SHA, followed by ServerHelloDone."""
    body = (
        _TLS10_VERSION
        + os.urandom(32)            # server random
        + b"\x00"                   # session id length: 0
        + _CIPHER_RC4_SHA           # selected cipher suite
        + b"\x00"                   # selected compression: null
    )
    server_hello = _handshake(0x02, body)
    server_hello_done = _handshake(0x0e, b"")
    return _tls_record(0x16, server_hello + server_hello_done)


def _change_cipher_spec() -> bytes:
    """ChangeCipherSpec record — signals the handshake is about to complete."""
    return _tls_record(0x14, b"\x01")


def _encrypted_finished() -> bytes:
    """Opaque (encrypted) Finished handshake record; contents are not parsed."""
    return _tls_record(0x16, os.urandom(40))


@register_code_rta(
    id="b32401d1-97b9-443a-be31-d1313a2663da",
    name="tls_deprecated_or_weak_cipher_negotiated_externally",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="d994a184-ab93-4cff-8fb6-31a4b4dd18b1",
            name="Deprecated TLS Version or Weak Cipher Negotiated Externally",
        )
    ],
    techniques=["T1557", "T1573"],
)
def main() -> None:
    """Forge a completed TLS 1.0 / RC4 handshake from an internal host to an external destination."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    src_port = random.randint(32768, 60000)
    c_isn = random.randint(0x10000000, 0x7FFFFFFF)
    s_isn = random.randint(0x10000000, 0x7FFFFFFF)

    def client(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            INTERNAL_SOURCE_IP, EXTERNAL_DEST_IP, src_port, TLS_PORT, flags, seq, ack, payload
        )

    def server(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            EXTERNAL_DEST_IP, INTERNAL_SOURCE_IP, TLS_PORT, src_port, flags, seq, ack, payload
        )

    client_hello = _client_hello()
    server_hello = _server_hello()
    client_finish = _change_cipher_spec() + _encrypted_finished()
    server_finish = _change_cipher_spec() + _encrypted_finished()

    # Track sequence numbers across both forged directions.
    c_seq = c_isn + 1   # after SYN consumes one sequence number
    s_seq = s_isn + 1   # after SYN/ACK consumes one sequence number

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    log.info(
        "Forging TLS 1.0 / RC4-SHA handshake %s -> %s:%d (deprecated TLS / weak cipher emulation)",
        INTERNAL_SOURCE_IP, EXTERNAL_DEST_IP, TLS_PORT,
    )

    try:
        # --- TCP three-way handshake ---
        _ = sock.sendto(client(_TCP_SYN, c_isn, 0), (EXTERNAL_DEST_IP, TLS_PORT))
        time.sleep(0.02)
        _ = sock.sendto(server(_TCP_SYNACK, s_isn, c_isn + 1), (INTERNAL_SOURCE_IP, src_port))
        time.sleep(0.02)
        _ = sock.sendto(client(_TCP_ACK, c_seq, s_seq), (EXTERNAL_DEST_IP, TLS_PORT))

        # --- TLS handshake ---
        _ = sock.sendto(client(_TCP_PSHACK, c_seq, s_seq, client_hello), (EXTERNAL_DEST_IP, TLS_PORT))
        c_seq += len(client_hello)
        time.sleep(0.02)

        _ = sock.sendto(server(_TCP_PSHACK, s_seq, c_seq, server_hello), (INTERNAL_SOURCE_IP, src_port))
        s_seq += len(server_hello)
        time.sleep(0.02)

        _ = sock.sendto(client(_TCP_PSHACK, c_seq, s_seq, client_finish), (EXTERNAL_DEST_IP, TLS_PORT))
        c_seq += len(client_finish)
        time.sleep(0.02)

        _ = sock.sendto(server(_TCP_PSHACK, s_seq, c_seq, server_finish), (INTERNAL_SOURCE_IP, src_port))
        s_seq += len(server_finish)
        time.sleep(0.02)

        # --- graceful close so the sensor emits the completed TLS event ---
        _ = sock.sendto(client(_TCP_FINACK, c_seq, s_seq), (EXTERNAL_DEST_IP, TLS_PORT))
        _ = sock.sendto(server(_TCP_FINACK, s_seq, c_seq + 1), (INTERNAL_SOURCE_IP, src_port))
        _ = sock.sendto(client(_TCP_ACK, c_seq + 1, s_seq + 1), (EXTERNAL_DEST_IP, TLS_PORT))

        log.info("Forged TLS 1.0 / RC4-SHA handshake emitted (tls.established=true expected)")
    except OSError as e:
        log.error("Failed to send forged TLS handshake: %s", e)
    finally:
        sock.close()
