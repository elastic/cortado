# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Repeated Stalled TLS Handshakes via ALPN acme-tls/1 Extension
# RTA: network_tls_alpn_acme_stalled_handshake.py
# Description: Emulates the CVE-2026-22045 goroutine-exhaustion DoS pattern by
#              opening THRESHOLD_COUNT real TCP connections to a minimal local
#              server. Each client sends a manually crafted TLS ClientHello
#              advertising acme-tls/1 as its sole ALPN extension. The server
#              deliberately sends no ServerHello.
#
#              The kernel performs a complete TCP handshake and graceful FIN
#              closure. Packetbeat / network_traffic with TLS parsing and
#              include_detailed_fields: true sees each connection as:
#                - tls.detailed.client_hello.extensions
#                    .application_layer_protocol_negotiation = "acme-tls/1"
#                - tls.established = false
#
#              Five events from the same source.ip + destination.ip pair fire
#              the threshold rule. All connections run in parallel so total
#              wall time is approximately STALL_SECONDS.
#
#              TCP/8443 must be free. No TLS server or raw-socket privileges are
#              required.

import logging
import socket
import ssl
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

TLS_PORT = 8443
STALL_SECONDS = 3           # remain below Packetbeat's 10-second transaction timeout
THRESHOLD_COUNT = 5         # matches the rule's threshold value

_ALPN_PROTOCOL = "acme-tls/1"

def _build_tls_client_hello() -> bytes:
    """Generate a standards-compliant ClientHello using the system TLS library."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols([_ALPN_PROTOCOL])

    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(
        incoming,
        outgoing,
        server_side=False,
        server_hostname="acme.invalid",
    )
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass

    client_hello = outgoing.read()
    if not client_hello:
        raise RuntimeError("TLS library did not generate a ClientHello")
    return client_hello


def _drain_connection(conn: socket.socket, peer: tuple[str, int]) -> None:
    """Read the ClientHello, send no TLS response, and close after client FIN."""
    conn.settimeout(STALL_SECONDS + 10)
    try:
        while conn.recv(4096):
            pass
    except (OSError, TimeoutError) as e:
        log.debug("TLS stub connection %s ended: %s", peer, e)
    finally:
        conn.close()


def _serve_connections(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    handlers: list[threading.Thread] = []
    try:
        for _ in range(THRESHOLD_COUNT):
            conn, peer = server.accept()
            handler = threading.Thread(
                target=_drain_connection,
                args=(conn, peer),
                daemon=True,
            )
            handler.start()
            handlers.append(handler)
    except OSError as e:
        log.error("TLS stub server error: %s", e)
    finally:
        for handler in handlers:
            handler.join(timeout=STALL_SECONDS + 10)
        server.close()


def _stalled_tls_client(host_ip: str) -> None:
    """Send a ClientHello, wait without a ServerHello, then close gracefully."""
    try:
        with socket.create_connection((host_ip, TLS_PORT), timeout=5) as conn:
            source_ip, source_port = conn.getsockname()
            conn.sendall(_build_tls_client_hello())
            log.debug("TLS ClientHello (acme-tls/1) sent from %s:%d", source_ip, source_port)
            time.sleep(STALL_SECONDS)
            conn.shutdown(socket.SHUT_WR)
            _ = conn.recv(1)
            log.debug("TLS client %s:%d closed with FIN", source_ip, source_port)
    except OSError as e:
        log.error("TLS client error: %s", e)


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
    """Emit five stalled acme-tls/1 ClientHellos over real TCP connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", TLS_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", TLS_PORT, e)
        server.close()
        return
    server.listen(THRESHOLD_COUNT)

    ready = threading.Event()
    server_thread = threading.Thread(
        target=_serve_connections,
        args=(server, ready),
        daemon=True,
    )
    server_thread.start()
    if not ready.wait(timeout=5):
        log.error("TLS listener did not start in time")
        server.close()
        return

    host_ip = get_host_ip()

    log.info(
        "Sending %d stalled TLS connections (acme-tls/1 ALPN) to %s:%d — stalling %ds",
        THRESHOLD_COUNT,
        host_ip,
        TLS_PORT,
        STALL_SECONDS,
    )

    threads: list[threading.Thread] = []
    for index in range(THRESHOLD_COUNT):
        t = threading.Thread(
            target=_stalled_tls_client,
            args=(host_ip,),
            daemon=True,
            name=f"acme-tls-client-{index}",
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=STALL_SECONDS + 10)

    server_thread.join(timeout=STALL_SECONDS + 10)
    log.info("Stalled handshake emulation complete")
