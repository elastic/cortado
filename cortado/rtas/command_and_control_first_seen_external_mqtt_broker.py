# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Seen External MQTT Broker Connection
# RTA: command_and_control_first_seen_external_mqtt_broker.py
# Description: Forges a complete bidirectional MQTT 3.1.1 CONNECT/CONNACK
#              transaction on the wire from an internal (RFC1918) source to a
#              public destination on TCP/1883. Suricata, Zeek, and PAN-OS App-ID
#              identify plaintext MQTT from this handshake (event_type=mqtt,
#              network.protocol=mqtt, or network.application=mqtt-base).
#
#              A local broker cannot be used because the rule excludes private
#              and special-purpose destination addresses, including TEST-NET
#              documentation ranges. Both directions are forged so a network
#              sensor can reassemble the client CONNECT and broker CONNACK.
#
#              The source address is randomized on each run so the
#              source.ip/destination.ip pair is new in the rule's 14-day
#              new-terms history window.
#
#              Flow: SYN -> SYN/ACK -> ACK -> client MQTT CONNECT ->
#              server MQTT CONNACK -> FIN/ACK exchange.
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

MQTT_PORT = 1883
PUBLIC_DESTINATION_IP = "8.8.8.8"
MQTT_CLIENT_ID = "cortado-rta"
MQTT_PROTOCOL_NAME = "MQTT"
MQTT_PROTOCOL_LEVEL = 4  # MQTT 3.1.1
MQTT_CONNECT_FLAGS = 0x02  # Clean Session
MQTT_KEEP_ALIVE_SECONDS = 60

_TCP_SYN = 0x02
_TCP_ACK = 0x10
_TCP_FIN = 0x01
_TCP_SYNACK = _TCP_SYN | _TCP_ACK
_TCP_PSHACK = 0x18
_TCP_FINACK = _TCP_FIN | _TCP_ACK

_MQTT_CONNECT = 0x10
_MQTT_CONNACK = 0x20


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return ~total & 0xFFFF


def _mqtt_remaining_length(value: int) -> bytes:
    if value < 0 or value > 268435455:
        raise ValueError("MQTT remaining length out of range")
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def _mqtt_string(value: str) -> bytes:
    encoded = value.encode("ascii")
    return struct.pack("!H", len(encoded)) + encoded


def _mqtt_connect() -> bytes:
    variable_header = (
        _mqtt_string(MQTT_PROTOCOL_NAME)
        + bytes((MQTT_PROTOCOL_LEVEL, MQTT_CONNECT_FLAGS))
        + struct.pack("!H", MQTT_KEEP_ALIVE_SECONDS)
    )
    payload = _mqtt_string(MQTT_CLIENT_ID)
    body = variable_header + payload
    return bytes((_MQTT_CONNECT,)) + _mqtt_remaining_length(len(body)) + body


def _mqtt_connack() -> bytes:
    # Session Present = 0, return code 0 (Connection Accepted).
    return bytes((_MQTT_CONNACK, 2, 0, 0))


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
    id="c8e4a19b-6f2d-4a71-9c53-1e0b7d4f8a26",
    name="command_and_control_first_seen_external_mqtt_broker",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="b6e05109-768e-4673-bc7b-6760912eb704",
            name="First Seen External MQTT Broker Connection",
        )
    ],
    techniques=["T1071", "T1071.005"],
)
def main() -> None:
    """Forge an internal-to-public MQTT CONNECT to a first-seen broker pair."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    source_ip = f"10.10.{random.randint(1, 254)}.{random.randint(1, 254)}"
    source_port = random.randint(32768, 60000)
    client_isn = random.randint(0x10000000, 0x7FFFFFFF)
    server_isn = random.randint(0x10000000, 0x7FFFFFFF)
    connect = _mqtt_connect()
    connack = _mqtt_connack()

    def client(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            source_ip,
            PUBLIC_DESTINATION_IP,
            source_port,
            MQTT_PORT,
            flags,
            seq,
            ack,
            payload,
        )

    def server(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            PUBLIC_DESTINATION_IP,
            source_ip,
            MQTT_PORT,
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
        "Forging MQTT CONNECT %s:%d -> %s:%d client_id=%s",
        source_ip,
        source_port,
        PUBLIC_DESTINATION_IP,
        MQTT_PORT,
        MQTT_CLIENT_ID,
    )
    try:
        _ = sock.sendto(client(_TCP_SYN, client_isn, 0), (PUBLIC_DESTINATION_IP, MQTT_PORT))
        time.sleep(0.02)
        _ = sock.sendto(server(_TCP_SYNACK, server_isn, client_isn + 1), (source_ip, source_port))
        time.sleep(0.02)
        _ = sock.sendto(client(_TCP_ACK, client_seq, server_seq), (PUBLIC_DESTINATION_IP, MQTT_PORT))

        _ = sock.sendto(
            client(_TCP_PSHACK, client_seq, server_seq, connect),
            (PUBLIC_DESTINATION_IP, MQTT_PORT),
        )
        client_seq += len(connect)
        time.sleep(0.02)
        _ = sock.sendto(
            server(_TCP_PSHACK, server_seq, client_seq, connack),
            (source_ip, source_port),
        )
        server_seq += len(connack)
        time.sleep(0.02)

        _ = sock.sendto(client(_TCP_FINACK, client_seq, server_seq), (PUBLIC_DESTINATION_IP, MQTT_PORT))
        _ = sock.sendto(server(_TCP_FINACK, server_seq, client_seq + 1), (source_ip, source_port))
        _ = sock.sendto(client(_TCP_ACK, client_seq + 1, server_seq + 1), (PUBLIC_DESTINATION_IP, MQTT_PORT))
        log.info("Forged MQTT CONNECT/CONNACK transaction emitted")
    except OSError as e:
        log.error("Failed to send forged MQTT transaction: %s", e)
    finally:
        sock.close()
