# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Inbound Connection to an Unsecure Elasticsearch Node
# RTA: inbound_connection_unsecure_elasticsearch_node.py
# Description: Emulates an inbound HTTP request to an unauthenticated Elasticsearch
#              node by standing up a localhost HTTP listener on TCP/9200 that responds
#              with HTTP 200 and an application/json body, then issuing a GET /
#              request to that listener WITHOUT an Authorization header.
#
#              This matches the Packetbeat/network_traffic path of the detection rule:
#              destination.port:9200, http.response.status_code:200,
#              NOT _exists_:http.request.headers.authorization, and the response
#              Content-Type is application/json (not image/x-icon).
#
#              TCP/9200 is unprivileged (>1024) so no special capabilities are
#              required. The Network Packet Capture integration must be configured
#              to decode HTTP on TCP/9200 with send_all_headers enabled for header
#              fields to be populated.

import http.client
import http.server
import logging
import threading
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

LOCALHOST = "127.0.0.1"
ELASTICSEARCH_PORT = 9200
FAKE_ES_BODY = b'{"name":"node-1","cluster_name":"elasticsearch","version":{"number":"8.0.0"}}'


class _UnsecuredElasticsearchHandler(http.server.BaseHTTPRequestHandler):
    """Respond to any GET with HTTP 200 and a JSON body, no auth required."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - http.server method name convention
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(FAKE_ES_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        _ = self.wfile.write(FAKE_ES_BODY)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server signature
        log.debug("listener: " + format, *args)


def _serve_one_request(server: http.server.HTTPServer, ready: threading.Event) -> None:
    ready.set()
    try:
        server.handle_request()
    finally:
        server.server_close()


@register_code_rta(
    id="8136e4fb-1c23-40c4-a385-519dedc209fa",
    name="inbound_connection_unsecure_elasticsearch_node",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="31295df3-277b-4c56-a1fb-84e31b4222a9",
            name="Inbound Connection to an Unsecure Elasticsearch Node",
        )
    ],
    techniques=["T1190", "T1595"],
)
def main() -> None:
    """Emit an unauthenticated HTTP GET to TCP/9200 and receive a 200 response."""
    http.server.HTTPServer.allow_reuse_address = True
    try:
        server = http.server.HTTPServer((LOCALHOST, ELASTICSEARCH_PORT), _UnsecuredElasticsearchHandler)
    except OSError as e:
        log.error("Could not bind %s:%d (%s)", LOCALHOST, ELASTICSEARCH_PORT, e)
        return

    ready = threading.Event()
    server_thread = threading.Thread(
        target=_serve_one_request, args=(server, ready), daemon=True
    )
    server_thread.start()

    if not ready.wait(timeout=5):
        log.error("Listener on TCP/%d did not start in time", ELASTICSEARCH_PORT)
        return

    time.sleep(0.2)

    log.info(
        "Sending unauthenticated GET / to %s:%d (unsecured Elasticsearch emulation)",
        LOCALHOST, ELASTICSEARCH_PORT,
    )
    conn = http.client.HTTPConnection(LOCALHOST, ELASTICSEARCH_PORT, timeout=5)
    try:
        # Deliberately omit Authorization header to match the detection condition.
        conn.request("GET", "/", headers={"Connection": "close"})
        resp = conn.getresponse()
        log.info(
            "Received HTTP %d from %s:%d (Content-Type: %s)",
            resp.status, LOCALHOST, ELASTICSEARCH_PORT, resp.getheader("Content-Type"),
        )
        _ = resp.read()
    except OSError as e:
        log.error("Request to %s:%d failed: %s", LOCALHOST, ELASTICSEARCH_PORT, e)
    finally:
        conn.close()

    server_thread.join(timeout=5)
