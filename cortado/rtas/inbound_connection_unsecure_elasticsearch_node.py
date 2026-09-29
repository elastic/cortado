# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Inbound Connection to an Unsecure Elasticsearch Node
# RTA: inbound_connection_unsecure_elasticsearch_node.py
# Description: Forges a complete bidirectional HTTP/1.1 transaction on the wire
#              from an EXTERNAL (public) source IP to an INTERNAL (RFC1918)
#              destination on TCP/9200, emulating an unauthenticated inbound
#              request to an Internet-exposed Elasticsearch node. The request
#              carries NO Authorization header and the response is HTTP 200 with
#              Content-Type: application/json - satisfying every field the rule
#              inspects: destination.port:9200, http.response.status_code:200,
#              Content-Type != image/x-icon, and no http.request.headers.authorization.
#
#              WHY THIS IS FORGED RATHER THAN A LOCAL LISTENER:
#              The rule requires network.direction:inbound. Packetbeat / the
#              network_traffic integration derives direction from the source and
#              destination IPs relative to its configured internal_networks:
#              external source + internal destination -> "inbound". A previous
#              version of this RTA stood up a local HTTP listener and connected to
#              the host's own IP; that flow has source == destination == the host
#              (both internal), which is classified "internal" (or interface-relative
#              "ingress"), NEVER "inbound", so the rule could not match. Forging the
#              flow from a genuinely external source (203.0.113.50, TEST-NET-3) to an
#              internal RFC1918 destination (10.10.10.10) is the only way to produce
#              an inbound-classified flow on a single host, and mirrors the approach
#              used by network_smb_from_internet.py.
#
#              SENSOR PREREQUISITE: network.direction:inbound requires the sensor to
#              have internal_networks configured (e.g. the RFC1918 ranges) so that
#              10.10.10.10 is recognised as internal and 203.0.113.50 as external.
#              Without internal_networks set, the integration falls back to
#              interface-relative "ingress"/"egress" and the rule's inbound clause
#              will not match regardless of the traffic generated here.
#
#              Both directions are forged as raw IP/TCP packets to a non-local
#              destination so they egress the physical NIC where the sensor
#              captures them and reassembles the transaction into
#              logs-network_traffic.http-*.
#
#              Flow: SYN -> SYN/ACK -> ACK -> client GET / (no auth) ->
#              server HTTP/1.1 200 (application/json) -> FIN/ACK exchange.
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

ELASTICSEARCH_PORT = 9200
EXTERNAL_SOURCE_IP = "203.0.113.50"   # public source -> classified external
INTERNAL_DEST_IP = "10.10.10.10"      # RFC1918 Elasticsearch node -> classified internal

FAKE_ES_BODY = b'{"name":"node-1","cluster_name":"elasticsearch","version":{"number":"8.0.0"}}'

# GET / with NO Authorization header -> matches "not http.request.headers.authorization: *"
HTTP_REQUEST = (
    b"GET / HTTP/1.1\r\n"
    b"Host: 10.10.10.10:9200\r\n"
    b"User-Agent: curl/8.0.0\r\n"
    b"Accept: */*\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# 200 with application/json (not image/x-icon) -> matches the rule's response clauses.
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(FAKE_ES_BODY)).encode("ascii") + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n" + FAKE_ES_BODY
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
    id="8136e4fb-1c23-40c4-a385-519dedc209fa",
    name="inbound_connection_unsecure_elasticsearch_node",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="31295df3-277b-4c56-a1fb-84e31b4222a9",
            name="Inbound Connection to an Unsecure Elasticsearch Node",
        )
    ],
    techniques=["T1190", "T1595"],
)
def main() -> None:
    """Forge an inbound (external->internal) unauthenticated HTTP GET / with a 200 response on TCP/9200."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    src_port = random.randint(32768, 60000)
    c_isn = random.randint(0x10000000, 0x7FFFFFFF)
    s_isn = random.randint(0x10000000, 0x7FFFFFFF)

    def client(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            EXTERNAL_SOURCE_IP, INTERNAL_DEST_IP, src_port, ELASTICSEARCH_PORT, flags, seq, ack, payload
        )

    def server(flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        return _build_raw_packet(
            INTERNAL_DEST_IP, EXTERNAL_SOURCE_IP, ELASTICSEARCH_PORT, src_port, flags, seq, ack, payload
        )

    c_seq = c_isn + 1   # after SYN consumes one sequence number
    s_seq = s_isn + 1   # after SYN/ACK consumes one sequence number

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    log.info(
        "Forging inbound unauthenticated GET / %s -> %s:%d (unsecure Elasticsearch emulation)",
        EXTERNAL_SOURCE_IP, INTERNAL_DEST_IP, ELASTICSEARCH_PORT,
    )
    try:
        # --- TCP three-way handshake ---
        _ = sock.sendto(client(_TCP_SYN, c_isn, 0), (INTERNAL_DEST_IP, ELASTICSEARCH_PORT))
        time.sleep(0.02)
        _ = sock.sendto(server(_TCP_SYNACK, s_isn, c_isn + 1), (EXTERNAL_SOURCE_IP, src_port))
        time.sleep(0.02)
        _ = sock.sendto(client(_TCP_ACK, c_seq, s_seq), (INTERNAL_DEST_IP, ELASTICSEARCH_PORT))

        # --- HTTP request (no auth) / response (200 application/json) ---
        _ = sock.sendto(client(_TCP_PSHACK, c_seq, s_seq, HTTP_REQUEST), (INTERNAL_DEST_IP, ELASTICSEARCH_PORT))
        c_seq += len(HTTP_REQUEST)
        time.sleep(0.02)
        _ = sock.sendto(server(_TCP_PSHACK, s_seq, c_seq, HTTP_RESPONSE), (EXTERNAL_SOURCE_IP, src_port))
        s_seq += len(HTTP_RESPONSE)
        time.sleep(0.02)

        # --- graceful close so the sensor emits the completed HTTP event ---
        _ = sock.sendto(client(_TCP_FINACK, c_seq, s_seq), (INTERNAL_DEST_IP, ELASTICSEARCH_PORT))
        _ = sock.sendto(server(_TCP_FINACK, s_seq, c_seq + 1), (EXTERNAL_SOURCE_IP, src_port))
        _ = sock.sendto(client(_TCP_ACK, c_seq + 1, s_seq + 1), (INTERNAL_DEST_IP, ELASTICSEARCH_PORT))

        log.info("Forged inbound unauthenticated Elasticsearch GET / (HTTP 200) emitted")
    except OSError as e:
        log.error("Failed to send forged HTTP transaction: %s", e)
    finally:
        sock.close()
