# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Seen External MQTT Broker Connection
# RTA: command_and_control_first_seen_external_mqtt_broker.py
# Description: Forges three internal-to-public TCP conversations that match the
#              plaintext and AWS IoT TLS branches of First Seen External MQTT
#              Broker Connection. The destination is a public address because
#              the rule excludes private and special-purpose destinations,
#              including TEST-NET. The source address is randomized on each run
#              so the source.ip/destination.ip pair is new in the 14-day
#              new-terms history window.
#
#              1. MQTT 3.1.1 CONNECT/CONNACK on TCP/1883. Suricata, Zeek, and
#                 PAN-OS App-ID identify plaintext MQTT from this handshake
#                 (event_type=mqtt, network.protocol=mqtt, or
#                 network.application=mqtt-base).
#
#              2. A completed TLS handshake on TCP/443. The ClientHello carries
#                 SNI plus ALPN x-amzn-mqtt-ca, the AWS IoT Core protocol for
#                 direct MQTT with X.509 client authentication. Packetbeat, with
#                 TLS parsing and include_detailed_fields, records
#                 tls.established=true, tls.client.server_name, and
#                 tls.detailed.client_hello.extensions
#                 .application_layer_protocol_negotiation.
#
#              3. A completed TLS handshake on TCP/8883 whose ClientHello SNI is
#                 a default account-specific AWS IoT ATS name
#                 (<prefix>-ats.iot.<region>.amazonaws.com).
#
#              Both directions are forged. Packetbeat sets tls.established only
#              after ChangeCipherSpec is seen from the directions that complete
#              the handshake, so each TLS flow includes ServerHello and
#              ChangeCipherSpec in both directions before the FIN exchange.
#
#              Flow: SYN -> SYN/ACK -> ACK -> application payloads ->
#              FIN/ACK exchange.
#
#              Requires CAP_NET_RAW (run as root or with the capability set).
#              The local kernel holds no TCP state for the forged conversations;
#              replies to the forged endpoints go nowhere, which is expected.
#              TLS capture must include TCP/443 and TCP/8883.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

MQTT_PORT = 1883
TLS_ALPN_PORT = 443
TLS_ATS_PORT = 8883
PUBLIC_DESTINATION_IP = "8.8.8.8"
MQTT_CLIENT_ID = "cortado-rta"
MQTT_PROTOCOL_NAME = "MQTT"
MQTT_PROTOCOL_LEVEL = 4  # MQTT 3.1.1
MQTT_CONNECT_FLAGS = 0x02  # Clean Session
MQTT_KEEP_ALIVE_SECONDS = 60
AWS_IOT_ALPN = "x-amzn-mqtt-ca"
AWS_IOT_ATS_SNI = "cortado-ats.iot.us-east-1.amazonaws.com"

_TCP_SYN = 0x02
_TCP_ACK = 0x10
_TCP_FIN = 0x01
_TCP_SYNACK = _TCP_SYN | _TCP_ACK
_TCP_PSHACK = 0x18
_TCP_FINACK = _TCP_FIN | _TCP_ACK

_MQTT_CONNECT = 0x10
_MQTT_CONNACK = 0x20

_TLS_MAJOR = 3
_TLS_MINOR = 3  # TLS 1.2
_TLS_HANDSHAKE = 0x16
_TLS_CHANGE_CIPHER_SPEC = 0x14
_TLS_CLIENT_HELLO = 0x01
_TLS_SERVER_HELLO = 0x02
_TLS_SERVER_HELLO_DONE = 0x0E
_TLS_AES128_SHA = b"\x00\x2f"
_EXT_SERVER_NAME = 0
_EXT_ALPN = 16


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


def _tls_record(content_type: int, body: bytes) -> bytes:
    return struct.pack("!BBBH", content_type, _TLS_MAJOR, _TLS_MINOR, len(body)) + body


def _handshake(msg_type: int, body: bytes) -> bytes:
    return struct.pack("!B", msg_type) + len(body).to_bytes(3, "big") + body


def _tls_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _sni_extension(hostname: str) -> bytes:
    host = hostname.encode("ascii")
    entry = bytes((0,)) + struct.pack("!H", len(host)) + host
    return _tls_extension(_EXT_SERVER_NAME, struct.pack("!H", len(entry)) + entry)


def _alpn_extension(protocols: tuple[str, ...]) -> bytes:
    names = b"".join(bytes((len(protocol),)) + protocol.encode("ascii") for protocol in protocols)
    # Packetbeat accepts ALPN only when the list length equals the rest of the extension.
    return _tls_extension(_EXT_ALPN, struct.pack("!H", len(names)) + names)


def _client_hello(server_name: str, alpn: tuple[str, ...] = ()) -> bytes:
    """TLS 1.2 ClientHello with SNI and, when provided, ALPN."""
    extensions = _sni_extension(server_name)
    if alpn:
        extensions += _alpn_extension(alpn)
    body = (
        bytes((_TLS_MAJOR, _TLS_MINOR))
        + os.urandom(32)
        + b"\x00"  # session id length
        + struct.pack("!H", len(_TLS_AES128_SHA))
        + _TLS_AES128_SHA
        + b"\x01\x00"  # null compression
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _tls_record(_TLS_HANDSHAKE, _handshake(_TLS_CLIENT_HELLO, body))


def _server_hello() -> bytes:
    """ServerHello selecting TLS 1.2 / AES128-SHA, followed by ServerHelloDone."""
    body = bytes((_TLS_MAJOR, _TLS_MINOR)) + os.urandom(32) + b"\x00" + _TLS_AES128_SHA + b"\x00"
    messages = _handshake(_TLS_SERVER_HELLO, body) + _handshake(_TLS_SERVER_HELLO_DONE, b"")
    return _tls_record(_TLS_HANDSHAKE, messages)


def _change_cipher_spec() -> bytes:
    return _tls_record(_TLS_CHANGE_CIPHER_SPEC, b"\x01")


def _encrypted_finished() -> bytes:
    """Opaque Finished record. Packetbeat stops parsing a direction at ChangeCipherSpec."""
    return _tls_record(_TLS_HANDSHAKE, os.urandom(40))


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


def _emit_exchange(
    sock: socket.socket,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    client_payloads: list[bytes],
    server_payloads: list[bytes],
) -> None:
    """Forge one bidirectional TCP conversation, including its handshake and close."""
    client_isn = random.randint(0x10000000, 0x7FFFFFFF)
    server_isn = random.randint(0x10000000, 0x7FFFFFFF)

    def client(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            flags,
            seq,
            ack,
            payload,
        )

    def server(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            destination_ip,
            source_ip,
            destination_port,
            source_port,
            flags,
            seq,
            ack,
            payload,
        )

    client_seq = client_isn + 1
    server_seq = server_isn + 1

    _ = sock.sendto(client(_TCP_SYN, client_isn, 0), (destination_ip, destination_port))
    time.sleep(0.02)
    _ = sock.sendto(server(_TCP_SYNACK, server_isn, client_isn + 1), (source_ip, source_port))
    time.sleep(0.02)
    _ = sock.sendto(client(_TCP_ACK, client_seq, server_seq), (destination_ip, destination_port))

    steps = max(len(client_payloads), len(server_payloads))
    for index in range(steps):
        if index < len(client_payloads):
            payload = client_payloads[index]
            _ = sock.sendto(
                client(_TCP_PSHACK, client_seq, server_seq, payload),
                (destination_ip, destination_port),
            )
            client_seq += len(payload)
            time.sleep(0.02)
        if index < len(server_payloads):
            payload = server_payloads[index]
            _ = sock.sendto(
                server(_TCP_PSHACK, server_seq, client_seq, payload),
                (source_ip, source_port),
            )
            server_seq += len(payload)
            time.sleep(0.02)

    _ = sock.sendto(client(_TCP_FINACK, client_seq, server_seq), (destination_ip, destination_port))
    _ = sock.sendto(server(_TCP_FINACK, server_seq, client_seq + 1), (source_ip, source_port))
    _ = sock.sendto(client(_TCP_ACK, client_seq + 1, server_seq + 1), (destination_ip, destination_port))


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
    """Forge plaintext MQTT and the two AWS IoT TLS routes to one new broker pair."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    source_ip = f"10.10.{random.randint(1, 254)}.{random.randint(1, 254)}"
    mqtt_port, alpn_port, ats_port = random.sample(range(32768, 60001), 3)
    alpn_hello = _client_hello(AWS_IOT_ATS_SNI, (AWS_IOT_ALPN,))
    ats_hello = _client_hello(AWS_IOT_ATS_SNI)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        log.info(
            "Forging MQTT CONNECT %s:%d -> %s:%d client_id=%s",
            source_ip,
            mqtt_port,
            PUBLIC_DESTINATION_IP,
            MQTT_PORT,
            MQTT_CLIENT_ID,
        )
        _emit_exchange(
            sock,
            source_ip,
            PUBLIC_DESTINATION_IP,
            mqtt_port,
            MQTT_PORT,
            [_mqtt_connect()],
            [_mqtt_connack()],
        )
        log.info("Forged MQTT CONNECT/CONNACK transaction emitted")

        log.info(
            "Forging AWS IoT TLS %s:%d -> %s:%d sni=%s alpn=%s",
            source_ip,
            alpn_port,
            PUBLIC_DESTINATION_IP,
            TLS_ALPN_PORT,
            AWS_IOT_ATS_SNI,
            AWS_IOT_ALPN,
        )
        _emit_exchange(
            sock,
            source_ip,
            PUBLIC_DESTINATION_IP,
            alpn_port,
            TLS_ALPN_PORT,
            [alpn_hello, _change_cipher_spec() + _encrypted_finished()],
            [_server_hello(), _change_cipher_spec() + _encrypted_finished()],
        )
        log.info("Forged TLS handshake on TCP/443 emitted (ALPN x-amzn-mqtt-ca)")

        log.info(
            "Forging AWS IoT TLS %s:%d -> %s:%d sni=%s",
            source_ip,
            ats_port,
            PUBLIC_DESTINATION_IP,
            TLS_ATS_PORT,
            AWS_IOT_ATS_SNI,
        )
        _emit_exchange(
            sock,
            source_ip,
            PUBLIC_DESTINATION_IP,
            ats_port,
            TLS_ATS_PORT,
            [ats_hello, _change_cipher_spec() + _encrypted_finished()],
            [_server_hello(), _change_cipher_spec() + _encrypted_finished()],
        )
        log.info("Forged TLS handshake on TCP/8883 emitted (AWS IoT ATS SNI)")
    except OSError as e:
        log.error("Failed to send forged MQTT or TLS transaction: %s", e)
    finally:
        sock.close()
