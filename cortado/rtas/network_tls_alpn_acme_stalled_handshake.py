# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Repeated Stalled TLS Handshakes via ALPN acme-tls/1 Extension
# RTA: network_tls_alpn_acme_stalled_handshake.py
# Description: Emulates the CVE-2026-22045 goroutine-exhaustion DoS pattern by
#              opening THRESHOLD_COUNT parallel TCP connections to a plain listener
#              on TCP/8443 via the host's non-loopback IP, each sending a manually
#              crafted TLS ClientHello that advertises acme-tls/1 as its sole ALPN
#              extension. The plain TCP server accepts each connection, holds it
#              open for STALL_SECONDS, then sends a fatal TLS Alert
#              (handshake_failure) before closing.
#
#              Packetbeat / network_traffic with TLS parsing and
#              include_detailed_fields: true sees each connection as:
#                - tls.detailed.client_hello.extensions
#                    .application_layer_protocol_negotiation = "acme-tls/1"
#                - tls.established = false  (no ServerHello sent)
#                - network.bytes < 1024     (ClientHello ~80B + Alert 7B ≈ 87 bytes total)
#                - event.duration >= 10000000000  (12 s > 10 s threshold)
#
#              Five such events from the same source.ip + destination.ip pair
#              fire the threshold rule. All connections run in parallel so total
#              wall time is approximately STALL_SECONDS.
#
#              The ClientHello is crafted from raw bytes rather than via the ssl
#              module, guaranteeing the ALPN extension contains exactly "acme-tls/1"
#              regardless of OpenSSL version or ssl context defaults.
#
#              After STALL_SECONDS the server sends a TLS Alert (fatal
#              handshake_failure) before closing. The server-side response is
#              required for Packetbeat to finalise and emit the TLS transaction
#              event; a silent close produces no event (unlike HTTP/Redis RTAs
#              whose fake servers always send a response).
#
#              TCP/8443 is unprivileged. Connections use the host's non-loopback IP
#              so traffic traverses the physical NIC where Packetbeat captures (same
#              approach as the inbound_connection_unsecure_elasticsearch_node RTA).

import logging
import os  # for os.urandom in _build_tls_client_hello
import socket
import struct
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

TLS_PORT = 8443
STALL_SECONDS = 12      # must exceed the rule's 10 s (10_000_000_000 ns) floor
THRESHOLD_COUNT = 5     # matches the rule's threshold value

# "acme-tls/1" encoded as bytes for the ALPN ProtocolName field
_ALPN_PROTOCOL = b"acme-tls/1"


def _build_tls_client_hello() -> bytes:
    """
    Build a minimal but well-formed TLS ClientHello with acme-tls/1 as
    the sole ALPN protocol. Uses os.urandom for the 32-byte client random
    so each of the five connections looks distinct on the wire.
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


# TLS Alert record — fatal handshake_failure (40 / 0x28).
# Sending a real TLS record causes Packetbeat to finalise and emit the session
# event. Without any server-side bytes Packetbeat silently discards stalled
# sessions and produces no event (same reason Redis/ES RTAs send +OK / HTTP 200).
_TLS_ALERT_HANDSHAKE_FAILURE = b"\x15\x03\x03\x00\x02\x02\x28"


def _stall_and_alert(conn: socket.socket) -> None:
    """Hold an accepted TCP connection, then send a fatal TLS Alert and close."""
    try:
        time.sleep(STALL_SECONDS)
        conn.sendall(_TLS_ALERT_HANDSHAKE_FAILURE)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _server_thread(server: socket.socket, ready: threading.Event) -> None:
    """Accept THRESHOLD_COUNT connections and stall each in its own thread."""
    ready.set()
    stall_threads: list[threading.Thread] = []
    try:
        for _ in range(THRESHOLD_COUNT):
            try:
                conn, addr = server.accept()
                log.debug("Accepted stalled connection from %s", addr)
                t = threading.Thread(target=_stall_and_alert, args=(conn,), daemon=True)
                t.start()
                stall_threads.append(t)
            except OSError as e:
                log.debug("Server accept error: %s", e)
                break
    finally:
        for t in stall_threads:
            t.join(timeout=STALL_SECONDS + 5)
        server.close()


def _client_stalled_hello(host: str, port: int) -> None:
    """Send a raw TLS ClientHello with acme-tls/1 ALPN and hold the connection open."""
    try:
        conn = socket.create_connection((host, port), timeout=STALL_SECONDS + 5)
    except OSError as e:
        log.error("Could not connect to %s:%d: %s", host, port, e)
        return

    try:
        hello = _build_tls_client_hello()
        conn.sendall(hello)
        # Block until the server closes (stall period expires), then exit
        conn.settimeout(STALL_SECONDS + 5)
        try:
            _ = conn.recv(4096)
        except OSError:
            pass
    except OSError as e:
        log.error("Client send error: %s", e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


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
    """Open 5 stalled TLS ClientHellos with acme-tls/1 ALPN on TCP/8443 to fire the threshold rule."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", TLS_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d (%s)", TLS_PORT, e)
        return
    server.listen(THRESHOLD_COUNT)

    ready = threading.Event()
    srv_thread = threading.Thread(target=_server_thread, args=(server, ready), daemon=True)
    srv_thread.start()

    if not ready.wait(timeout=5):
        log.error("Listener on TCP/%d did not start in time", TLS_PORT)
        return

    time.sleep(0.1)

    local_ip = get_host_ip()
    log.info(
        "Opening %d stalled TLS ClientHellos (acme-tls/1 ALPN) to %s:%d — stalling %ds each",
        THRESHOLD_COUNT, local_ip, TLS_PORT, STALL_SECONDS,
    )

    client_threads: list[threading.Thread] = []
    for i in range(THRESHOLD_COUNT):
        t = threading.Thread(
            target=_client_stalled_hello,
            args=(local_ip, TLS_PORT),
            daemon=True,
            name=f"acme-tls-client-{i}",
        )
        t.start()
        client_threads.append(t)

    for t in client_threads:
        t.join(timeout=STALL_SECONDS + 10)

    srv_thread.join(timeout=5)
    log.info("Stalled handshake emulation complete")
