# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential NetScaler Configuration File or Archive Retrieval
# RTA: collection_netscaler_configuration_archive_http_retrieval.py
# Description: Serves one harmless local HTTP response and requests a synthetic
#              NetScaler archive path over the host's non-loopback interface.
#              The completed GET/200 transaction is visible to Network Packet
#              Capture and contains no real configuration or archive data.
#
#              The rule requires the event tag `netscaler-destination`. Before
#              running this RTA, configure the integration's trusted test-asset
#              enrichment to add that tag for this host's destination address.
#              Network Packet Capture must also decode HTTP on TCP/8080.

import http.client
import http.server
import logging
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

HTTP_PORT = 8080
ARCHIVE_PATH = "/logon/LogonPoint/elastic-rta.tgz"
RESPONSE_BODY = b"elastic-rta-placeholder\n"


class _ArchiveHandler(http.server.BaseHTTPRequestHandler):
    """Return a harmless body for the synthetic NetScaler archive path."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - http.server method name convention
        if self.path != ARCHIVE_PATH:
            self.send_error(404, "Not Found")
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/gzip")
        self.send_header("Content-Length", str(len(RESPONSE_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        _ = self.wfile.write(RESPONSE_BODY)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server signature
        log.debug("listener: " + format, *args)


def _serve_one_request(server: http.server.HTTPServer, ready: threading.Event) -> None:
    ready.set()
    try:
        server.handle_request()
    finally:
        server.server_close()


@register_code_rta(
    id="ca0b6555-faf1-4e1c-973c-25abb9b41a1d",
    name="collection_netscaler_configuration_archive_http_retrieval",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="d90564ec-13cc-4e57-906c-2e2dc90f128f",
            name="Potential NetScaler Configuration File or Archive Retrieval",
        )
    ],
    techniques=["T1602", "T1602.002"],
)
def main() -> None:
    """Generate a successful HTTP GET for a synthetic NetScaler archive."""
    http.server.HTTPServer.allow_reuse_address = True
    try:
        server = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), _ArchiveHandler)
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", HTTP_PORT, e)
        return

    server.timeout = 5
    ready = threading.Event()
    server_thread = threading.Thread(
        target=_serve_one_request,
        args=(server, ready),
        daemon=True,
    )
    server_thread.start()
    if not ready.wait(timeout=5):
        log.error("HTTP listener did not start in time")
        server.server_close()
        return

    time.sleep(0.1)
    host_ip = get_host_ip()
    log.info("Requesting synthetic NetScaler archive from http://%s:%d%s", host_ip, HTTP_PORT, ARCHIVE_PATH)

    connection = http.client.HTTPConnection(host_ip, HTTP_PORT, timeout=5)
    try:
        connection.request("GET", ARCHIVE_PATH, headers={"Connection": "close"})
        response = connection.getresponse()
        _ = response.read()
        if response.status != 200:
            raise ValueError(f"Expected HTTP 200 response, received {response.status}")
        log.info("Synthetic NetScaler archive GET completed with HTTP 200")
    except (OSError, TimeoutError, ValueError) as e:
        log.error("HTTP transaction failed: %s", e)
    finally:
        connection.close()

    server_thread.join(timeout=5)
