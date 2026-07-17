# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Cobalt Strike Command and Control Beacon
# RTA: command_and_control_cobalt_strike_beacon.py
# Description: Forges a raw TLS ClientHello on the wire whose SNI (server_name)
#              matches the Cobalt Strike staging domain pattern the rule keys on:
#              [a-z]{3}.stage.[0-9]{8}.* (e.g. "abc.stage.12345678.com"). The
#              network sensor (Packetbeat / network_traffic TLS parser) reads the
#              SNI from the ClientHello and the network_traffic.tls ingest pipeline
#              copies it into destination.domain, which is the field the detection
#              rule matches with RLIKE.
#
#              The flow is emitted as raw IP/TCP packets to a NON-LOCAL, documentation
#              -range destination (TEST-NET-3, 203.0.113.0/24) so the packets egress
#              the physical NIC where the sensor captures them. A same-host
#              connection to get_host_ip() would route over loopback (lo), which the
#              sensor does not observe, so raw sockets to a non-local destination are
#              required. The source is spoofed; the local kernel holds no TCP state
#              for the conversation and any reply goes nowhere, which is expected.
#
#              Flow: SYN -> PSH+ACK (TLS ClientHello with the staging SNI) -> RST.
#              tls.established is false (no ServerHello), but the SNI - and therefore
#              destination.domain - is populated from the ClientHello regardless.
#
#              Requires CAP_NET_RAW (run as root or with the capability set).

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

TLS_PORT = 443
# Spoofed internal client; destination is a non-local documentation-range IP so
# the packets leave via the physical NIC and are captured by the sensor.
SPOOFED_SOURCE_IP = "10.10.10.20"
EXTERNAL_DEST_IP = "203.0.113.10"

# Matches the rule regex [a-z]{3}\.stage\.[0-9]{8}\..* : 3 lowercase letters,
# ".stage.", 8 digits, then a TLD.
STAGING_SNI = "abc.stage.12345678.com"

_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_PSHACK = 0x18  # PSH | ACK


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


def _sni_extension(hostname: str) -> bytes:
    """Build a TLS server_name (SNI) extension for the given hostname."""
    name = hostname.encode("ascii")
    server_name = b"\x00" + struct.pack("!H", len(name)) + name  # host_name(0) + len + name
    server_name_list = struct.pack("!H", len(server_name)) + server_name
    return b"\x00\x00" + struct.pack("!H", len(server_name_list)) + server_name_list


def _client_hello(sni: str) -> bytes:
    """Build a minimal well-formed TLS 1.2 ClientHello carrying the given SNI."""
    extensions = _sni_extension(sni)
    body = (
        b"\x03\x03"                              # ClientHello version: TLS 1.2
        + os.urandom(32)                         # client random
        + b"\x00"                               # session id length: 0
        + b"\x00\x04"                           # cipher suites length: 4
        + b"\x13\x01"                           # TLS_AES_128_GCM_SHA256
        + b"\x00\x2f"                           # TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01\x00"                           # 1 compression method: null
        + struct.pack("!H", len(extensions))    # extensions length
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body  # ClientHello + 3-byte len
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake  # record, ver TLS 1.0


@register_code_rta(
    id="c65fb395-4915-4b57-82f2-b79ee50d38a8",
    name="command_and_control_cobalt_strike_beacon",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="cf53f532-9cc9-445a-9ae7-fced307ec53c",
            name="Cobalt Strike Command and Control Beacon",
        )
    ],
    techniques=["T1071", "T1071.001", "T1568", "T1568.002"],
)
def main() -> None:
    """Emit a raw TLS ClientHello whose SNI matches the Cobalt Strike staging-domain pattern."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    src_port = random.randint(32768, 60000)
    isn = random.randint(0x10000000, 0x7FFFFFFF)
    client_hello = _client_hello(STAGING_SNI)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    log.info(
        "Forging TLS ClientHello with SNI %s -> %s:%d (Cobalt Strike C2 beacon emulation)",
        STAGING_SNI, EXTERNAL_DEST_IP, TLS_PORT,
    )
    try:
        # SYN opens the flow.
        _ = sock.sendto(
            _build_raw_packet(SPOOFED_SOURCE_IP, EXTERNAL_DEST_IP, src_port, TLS_PORT, _TCP_SYN, isn, 0),
            (EXTERNAL_DEST_IP, TLS_PORT),
        )
        time.sleep(0.05)
        # PSH+ACK carries the ClientHello with the staging SNI.
        _ = sock.sendto(
            _build_raw_packet(
                SPOOFED_SOURCE_IP, EXTERNAL_DEST_IP, src_port, TLS_PORT, _TCP_PSHACK, isn + 1, 1, client_hello
            ),
            (EXTERNAL_DEST_IP, TLS_PORT),
        )
        time.sleep(0.05)
        # RST closes the flow so the sensor emits the TLS event.
        _ = sock.sendto(
            _build_raw_packet(
                SPOOFED_SOURCE_IP, EXTERNAL_DEST_IP, src_port, TLS_PORT, _TCP_RST, isn + 1 + len(client_hello), 1
            ),
            (EXTERNAL_DEST_IP, TLS_PORT),
        )
        log.info("Forged Cobalt Strike SNI ClientHello emitted (destination.domain=%s expected)", STAGING_SNI)
    except OSError as e:
        log.error("Failed to send forged ClientHello: %s", e)
    finally:
        sock.close()
