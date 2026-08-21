# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Self-Signed TLS Certificate Recently Issued on External Connection
# RTA: network_tls_self_signed_recent_external_connection.py
# Description: Completes a real TLS handshake from an internal client address
#              to a locally assigned public destination address. The listener
#              presents an ephemeral self-signed certificate (issuer DN equals
#              subject DN, not_before is now) so Packetbeat / network_traffic.tls
#              emits tls.established=true with tls.server.x509.* populated.
#
#              A public destination is required because the rule excludes RFC1918,
#              documentation, and other reserved ranges. Spoofed TLS records are
#              not used: Packetbeat rejects synthetically framed handshakes and
#              records them as flow-only events. The public address is added as a
#              /32 on the host's primary interface and removed afterward, so no
#              external host is contacted.
#
#              Requires root (bind TCP/443 and ip addr) and openssl.

import ipaddress
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
PUBLIC_SERVER_IP = "1.2.3.4"
CERTIFICATE_CN = "rta-c2.example.com"
INTERNAL_SOURCE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _generate_self_signed_cert(dir_path: str, common_name: str) -> tuple[str, str]:
    """Mint an ephemeral self-signed cert/key with openssl for the local TLS listener."""
    cert_path = os.path.join(dir_path, "cert.pem")
    key_path = os.path.join(dir_path, "key.pem")
    _ = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "7",
            "-nodes",
            "-subj",
            f"/CN={common_name}",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


def _is_internal_source(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in network for network in INTERNAL_SOURCE_NETWORKS)


def _interface_for_address(ip: str) -> str | None:
    completed = subprocess.run(["ip", "-o", "addr", "show"], check=False, capture_output=True, text=True)
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet" and parts[3].startswith(f"{ip}/"):
            return parts[1]
    return None


def _address_is_local(ip: str) -> bool:
    completed = subprocess.run(["ip", "-o", "addr", "show", "to", ip], check=False, capture_output=True, text=True)
    return ip in completed.stdout


def _add_local_address(ip: str, iface: str) -> None:
    _ = subprocess.run(
        ["ip", "addr", "add", f"{ip}/32", "dev", iface, "noprefixroute"],
        check=True,
        capture_output=True,
    )


def _delete_local_address(ip: str, iface: str) -> None:
    _ = subprocess.run(
        ["ip", "addr", "del", f"{ip}/32", "dev", iface],
        check=False,
        capture_output=True,
    )


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
    id="432d799e-65de-4ca2-89e0-5d98b5820fa3",
    name="network_tls_self_signed_recent_external_connection",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="869fe008-5dd4-4f07-9c2e-aa90c3926fd9",
            name="Self-Signed TLS Certificate Recently Issued on External Connection",
        )
    ],
    techniques=["T1071", "T1573", "T1573.002"],
)
def main() -> None:
    """Complete a TLS handshake to a locally assigned public IP with a fresh self-signed cert."""
    if os.geteuid() != 0:
        log.error("Root is required to bind TCP/%d and add a local public address", TLS_PORT)
        return
    if shutil.which("openssl") is None:
        log.error("openssl is required to mint the ephemeral TLS certificate")
        return
    if shutil.which("ip") is None:
        log.error("iproute2 is required to assign the public destination address locally")
        return

    host_ip = get_host_ip()
    if not _is_internal_source(host_ip):
        log.error("Host IP %s is not an internal source range required by the rule", host_ip)
        return
    iface = _interface_for_address(host_ip)
    if iface is None:
        log.error("Could not determine the interface that owns %s", host_ip)
        return

    added_public_address = False
    if not _address_is_local(PUBLIC_SERVER_IP):
        try:
            _add_local_address(PUBLIC_SERVER_IP, iface)
            added_public_address = True
        except subprocess.CalledProcessError as e:
            log.error("Failed to add %s to %s: %s", PUBLIC_SERVER_IP, iface, e)
            return
    if not _address_is_local(PUBLIC_SERVER_IP):
        log.error("Refusing to connect: %s is not assigned locally", PUBLIC_SERVER_IP)
        return

    tmp_dir = tempfile.mkdtemp(prefix="tls-selfsigned-")
    try:
        cert_path, key_path = _generate_self_signed_cert(tmp_dir, CERTIFICATE_CN)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((PUBLIC_SERVER_IP, TLS_PORT))
        except OSError as e:
            log.error("Could not bind %s:%d (%s)", PUBLIC_SERVER_IP, TLS_PORT, e)
            server.close()
            return
        server.listen(1)

        ready = threading.Event()
        server_thread = threading.Thread(target=_serve_one_tls, args=(server, server_ctx, ready), daemon=True)
        server_thread.start()
        if not ready.wait(timeout=5):
            log.error("TLS listener on %s:%d did not start in time", PUBLIC_SERVER_IP, TLS_PORT)
            return
        time.sleep(0.2)

        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        log.info(
            "Performing TLS handshake %s -> %s:%d with self-signed CN=%s",
            host_ip,
            PUBLIC_SERVER_IP,
            TLS_PORT,
            CERTIFICATE_CN,
        )
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        try:
            raw.bind((host_ip, 0))
            raw.connect((PUBLIC_SERVER_IP, TLS_PORT))
            tls = client_ctx.wrap_socket(raw, server_hostname=CERTIFICATE_CN)
            try:
                _ = tls.send(b"beacon")
                _ = tls.recv(1024)
            finally:
                tls.close()
            log.info("Completed self-signed TLS handshake to public destination %s", PUBLIC_SERVER_IP)
        except OSError as e:
            log.error("TLS handshake to %s:%d failed: %s", PUBLIC_SERVER_IP, TLS_PORT, e)
            raw.close()

        server_thread.join(timeout=5)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        if added_public_address:
            _delete_local_address(PUBLIC_SERVER_IP, iface)
