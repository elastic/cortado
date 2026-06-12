# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Repeated Stalled TLS Handshakes via ALPN acme-tls/1 Extension
# RTA: network_tls_alpn_acme_stalled_handshake.py
# Description: Emulates the CVE-2026-22045 goroutine-exhaustion DoS pattern by
#              opening THRESHOLD_COUNT parallel TLS connections to a plain TCP
#              listener on TCP/8443 via the host's non-loopback IP. Each client
#              uses ssl.SSLContext.set_alpn_protocols(["acme-tls/1"]) so that
#              Python constructs a proper TLS ClientHello advertising the
#              acme-tls/1 ALPN extension. The plain TCP server accepts each
#              connection and holds it open for STALL_SECONDS without sending
#              a TLS ServerHello, causing the client's do_handshake() to block.
#
#              Packetbeat / network_traffic with TLS parsing and
#              include_detailed_fields: true sees each connection as:
#                - tls.detailed.client_hello.extensions
#                    .application_layer_protocol_negotiation = "acme-tls/1"
#                - tls.established = false  (no ServerHello received)
#                - network.bytes < 1024     (only ClientHello bytes sent)
#                - event.duration >= 10000000000  (12 s > 10 s threshold)
#
#              Five such events from the same source.ip + destination.ip pair
#              fire the threshold rule. All connections run in parallel so total
#              wall time is approximately STALL_SECONDS.
#
#              TCP/8443 is unprivileged. Connections use the host's non-loopback
#              IP so traffic traverses the physical NIC where Packetbeat captures.

import logging
import socket
import ssl
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

TLS_PORT = 8443
STALL_SECONDS = 12      # must exceed the rule's 10 s (10_000_000_000 ns) minimum
THRESHOLD_COUNT = 5     # matches the rule's threshold value


def _stall_connection(conn: socket.socket) -> None:
    """Hold an accepted TCP connection open without responding, then close."""
    try:
        time.sleep(STALL_SECONDS)
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
                log.debug("Accepted stalled TLS connection from %s", addr)
                t = threading.Thread(target=_stall_connection, args=(conn,), daemon=True)
                t.start()
                stall_threads.append(t)
            except OSError as e:
                log.debug("Server accept error: %s", e)
                break
    finally:
        for t in stall_threads:
            t.join(timeout=STALL_SECONDS + 5)
        server.close()


def _client_stalled_hello(host: str, port: int, ctx: ssl.SSLContext) -> None:
    """Connect with SSL (sends ClientHello with acme-tls/1 ALPN) and let the handshake stall."""
    try:
        raw = socket.create_connection((host, port), timeout=STALL_SECONDS + 5)
    except OSError as e:
        log.error("Could not connect to %s:%d: %s", host, port, e)
        return

    ssl_sock = ctx.wrap_socket(raw, server_hostname=None, do_handshake_on_connect=False)
    try:
        ssl_sock.do_handshake()
    except (ssl.SSLError, OSError) as e:
        # Expected — server closes without sending ServerHello after STALL_SECONDS
        log.debug("Handshake stall ended (expected): %s", e)
    finally:
        try:
            ssl_sock.close()
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
    """Open 5 stalled TLS ClientHellos with acme-tls/1 ALPN to trigger the threshold rule."""
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

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["acme-tls/1"])

    local_ip = get_host_ip()
    log.info(
        "Opening %d stalled TLS ClientHellos (acme-tls/1 ALPN) to %s:%d — stalling %ds each",
        THRESHOLD_COUNT, local_ip, TLS_PORT, STALL_SECONDS,
    )

    client_threads: list[threading.Thread] = []
    for i in range(THRESHOLD_COUNT):
        t = threading.Thread(
            target=_client_stalled_hello,
            args=(local_ip, TLS_PORT, ctx),
            daemon=True,
            name=f"acme-tls-client-{i}",
        )
        t.start()
        client_threads.append(t)

    for t in client_threads:
        t.join(timeout=STALL_SECONDS + 10)

    srv_thread.join(timeout=5)
    log.info("Stalled handshake emulation complete")
