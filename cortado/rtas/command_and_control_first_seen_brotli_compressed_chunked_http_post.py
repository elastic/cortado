# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First-Seen Brotli-Compressed Chunked HTTP POST to Destination
# RTA: command_and_control_first_seen_brotli_compressed_chunked_http_post.py
# Description: Sends a real HTTP/1.1 POST to a local listener over the host's
#              non-loopback address. The request uses Content-Encoding: br and
#              Transfer-Encoding: chunked, matching the headers required by the
#              network_traffic.http new-terms rule.
#
#              The one-byte body is a valid Brotli stream representing an empty
#              payload. A complete HTTP 204 response closes the transaction so
#              Network Packet Capture can emit the decoded HTTP event.
#
#              The Network Packet Capture HTTP analyzer must inspect TCP/8080
#              and export Content-Encoding and Transfer-Encoding via send_headers
#              (or send_all_headers).

import logging
import socket
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

HTTP_PORT = 8080
REQUEST_PATH = "/cortado/brotli-chunked"

# RFC 7932 Brotli stream for an empty payload.
_BROTLI_BODY = b"\x3b"


def _chunked_request(host_ip: str) -> bytes:
    headers = (
        f"POST {REQUEST_PATH} HTTP/1.1\r\n"
        f"Host: {host_ip}:{HTTP_PORT}\r\n"
        "User-Agent: cortado-rta/1.0\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Encoding: br\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    chunked_body = f"{len(_BROTLI_BODY):X}\r\n".encode() + _BROTLI_BODY + b"\r\n0\r\n\r\n"
    return headers + chunked_body


def _serve_request(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    try:
        conn, peer = server.accept()
        log.debug("Accepted HTTP connection from %s", peer)
        with conn:
            conn.settimeout(5)
            request = bytearray()
            while b"\r\n0\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                request.extend(chunk)
                if len(request) > 65536:
                    raise ValueError("HTTP request exceeded maximum expected size")

            request_lower = bytes(request).lower()
            if not request_lower.startswith(f"post {REQUEST_PATH} http/1.1\r\n".encode()):
                raise ValueError("Expected Brotli chunked HTTP POST request")
            if b"\r\ncontent-encoding: br\r\n" not in request_lower:
                raise ValueError("Expected Content-Encoding: br header")
            if b"\r\ntransfer-encoding: chunked\r\n" not in request_lower:
                raise ValueError("Expected Transfer-Encoding: chunked header")

            conn.sendall(
                b"HTTP/1.1 204 No Content\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
    except (OSError, TimeoutError, ValueError) as e:
        log.error("HTTP listener error: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="7e166f54-19cd-4d24-a255-73f245287750",
    name="command_and_control_first_seen_brotli_compressed_chunked_http_post",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="3b3f80f0-6d80-4303-ac53-b410f8aa2c7d",
            name="First-Seen Brotli-Compressed Chunked HTTP POST to Destination",
        )
    ],
    techniques=["T1071", "T1071.001"],
)
def main() -> None:
    """Send a Brotli-compressed HTTP POST using chunked transfer encoding."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", HTTP_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", HTTP_PORT, e)
        server.close()
        return
    server.listen(1)

    ready = threading.Event()
    server_thread = threading.Thread(
        target=_serve_request,
        args=(server, ready),
        daemon=True,
    )
    server_thread.start()
    if not ready.wait(timeout=5):
        log.error("HTTP listener did not start in time")
        server.close()
        return

    time.sleep(0.1)
    host_ip = get_host_ip()
    log.info(
        "Sending Brotli-compressed chunked HTTP POST to %s:%d%s",
        host_ip,
        HTTP_PORT,
        REQUEST_PATH,
    )

    try:
        with socket.create_connection((host_ip, HTTP_PORT), timeout=5) as conn:
            conn.sendall(_chunked_request(host_ip))
            response = conn.recv(4096)
            if not response.startswith(b"HTTP/1.1 204"):
                raise ValueError("Expected HTTP 204 response")
            log.info("Brotli-compressed chunked HTTP POST completed")
    except (OSError, TimeoutError, ValueError) as e:
        log.error("HTTP client error: %s", e)

    server_thread.join(timeout=5)
