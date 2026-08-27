# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Possible FIN7 DGA Command and Control Behavior
# RTA: command_and_control_fin7_dga_beacon.py
# Description: Performs a REAL TLS handshake whose ClientHello SNI (server_name)
#              matches the FIN7 DGA domain pattern the rule keys on:
#              [a-zA-Z]{4,5}.(pw|us|club|info|site|top) (e.g. "abcde.top"), while
#              deliberately avoiding the rule's zoom.us exclusion. A local TLS
#              listener presents an ephemeral self-signed certificate on TCP/443
#              and a local client connects to the host's non-loopback IP with
#              server_hostname set to the DGA domain, so a genuine, fully-parseable
#              handshake traverses the physical interface where the sensor
#              (Packetbeat / network_traffic TLS parser) observes it. The
#              network_traffic.tls ingest pipeline copies the SNI into
#              destination.domain, the field the detection rule matches with RLIKE.
#
#              WHY A REAL HANDSHAKE RATHER THAN FORGED RAW PACKETS:
#              An earlier version forged a raw IP/TCP TLS handshake. The sensor
#              recorded it only as a bare network_traffic.flow event and never
#              emitted a network_traffic.tls document, because Packetbeat's TLS
#              parser rejects a synthetically framed handshake. This lab parses
#              thousands of genuine TLS sessions on TCP/443, so producing a real
#              handshake with the Python ssl module - the same local-listener
#              pattern proven to be captured by the cPanel / Elasticsearch RTAs -
#              is what makes the sensor emit a parsed tls event carrying the SNI.
#
#              SNI is chosen by the client regardless of the certificate the
#              server presents, so the self-signed cert's subject is irrelevant;
#              destination.domain is populated from server_hostname on the wire.
#
#              TCP/443 is privileged, so the listener requires root (or
#              CAP_NET_BIND_SERVICE). TCP/443 is also the port this sensor is
#              already parsing for TLS, so the handshake is deep-parsed rather than
#              recorded as flow-only. openssl must be available to mint the
#              ephemeral certificate.

import logging
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

TLS_PORT = 443
# Matches the rule regex [a-zA-Z]{4,5}\.(pw|us|club|info|site|top) : 4-5 letters
# followed by a flagged TLD. Chosen so it is NOT zoom.us (the rule's exclusion).
DGA_SNI = "abcde.top"


def _generate_self_signed_cert(dir_path: str, common_name: str) -> tuple[str, str]:
    """Mint an ephemeral self-signed cert/key with openssl for the local TLS listener."""
    cert_path = os.path.join(dir_path, "cert.pem")
    key_path = os.path.join(dir_path, "key.pem")
    _ = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes", "-subj", f"/CN={common_name}",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


def _serve_one_tls(server: socket.socket, ctx: ssl.SSLContext, ready: threading.Event) -> None:
    """Accept a single connection, complete the TLS handshake, then close."""
    ready.set()
    try:
        conn, _ = server.accept()
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            try:
                _ = tls_conn.recv(1024)
                _ = tls_conn.send(b"OK")
            finally:
                tls_conn.close()
        except ssl.SSLError as e:
            log.debug("server-side TLS handshake ended: %s", e)
        finally:
            conn.close()
    except OSError as e:
        log.debug("listener accept ended: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="b66f8366-4015-4333-816f-66eadfa970d5",
    name="command_and_control_fin7_dga_beacon",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="4a4e23cf-78a2-449c-bac3-701924c269d3",
            name="Possible FIN7 DGA Command and Control Behavior",
        )
    ],
    techniques=["T1071", "T1071.001", "T1568", "T1568.002"],
)
def main() -> None:
    """Perform a real TLS handshake whose SNI matches the FIN7 DGA domain pattern."""
    if os.geteuid() != 0:
        log.error("Binding TCP/%d requires root (or CAP_NET_BIND_SERVICE)", TLS_PORT)
        return
    if shutil.which("openssl") is None:
        log.error("openssl is required to mint the ephemeral TLS certificate")
        return

    tmp_dir = tempfile.mkdtemp(prefix="fin7-dga-tls-")
    try:
        cert_path, key_path = _generate_self_signed_cert(tmp_dir, DGA_SNI)

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", TLS_PORT))
        except OSError as e:
            log.error("Could not bind 0.0.0.0:%d (%s)", TLS_PORT, e)
            server.close()
            return
        server.listen(1)

        ready = threading.Event()
        server_thread = threading.Thread(target=_serve_one_tls, args=(server, server_ctx, ready), daemon=True)
        server_thread.start()
        if not ready.wait(timeout=5):
            log.error("TLS listener on TCP/%d did not start in time", TLS_PORT)
            return
        time.sleep(0.2)

        host_ip = get_host_ip()
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        log.info(
            "Performing TLS handshake to %s:%d with SNI %s (FIN7 DGA C2 emulation)",
            host_ip, TLS_PORT, DGA_SNI,
        )
        try:
            raw = socket.create_connection((host_ip, TLS_PORT), timeout=5)
            # server_hostname sets the ClientHello SNI regardless of certificate validation.
            tls = client_ctx.wrap_socket(raw, server_hostname=DGA_SNI)
            try:
                _ = tls.send(b"beacon")
                _ = tls.recv(1024)
            finally:
                tls.close()
            log.info("FIN7 DGA TLS handshake with SNI %s completed (destination.domain expected)", DGA_SNI)
        except OSError as e:
            log.error("TLS handshake to %s:%d failed: %s", host_ip, TLS_PORT, e)

        server_thread.join(timeout=5)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
