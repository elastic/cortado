# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Abnormally Large DNS Response (Linux)
# RTA: linux_dns_server_overflow.py
# Description: Emulates the network shape of CVE-2020-1350 (SigRed) by
#              producing a flow with destination.port=53 where the server
#              (destination) sends >= 65,000 bytes back to the client. Stands
#              up a localhost TCP listener on port 53 and connects to it,
#              with the listener writing ~70 KiB of payload to the client.
#              The resulting flow record (network_traffic / Zeek) shows
#              destination.port=53 and destination.bytes above the
#              65,000-byte threshold the rule looks for (raised from 60,000
#              in detection-rules PR #6201). The flow completes in well under
#              60 seconds, so it is not removed by the rule's new long-lived
#              flow_terminated / network_flow exclusion.
#
#              Binding TCP/53 requires CAP_NET_BIND_SERVICE / root.

import logging
import os
import socket
import threading
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

DNS_PORT = 53
LOCALHOST = "127.0.0.1"
RESPONSE_SIZE = 70 * 1024  # >= 65_000 bytes triggers the rule (threshold raised in PR #6201)


def _serve_large_response(ready: threading.Event) -> None:
    """Bind localhost:53 and write a >60KB payload to the first client that connects."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((LOCALHOST, DNS_PORT))
        server.listen(1)
        server.settimeout(10)
        ready.set()
        conn, addr = server.accept()
        log.info("Accepted client %s on TCP/%d - sending %d-byte payload", addr, DNS_PORT, RESPONSE_SIZE)
        try:
            # Sending in a single large buffer so the flow accounts >= 65KB on the
            # destination -> source direction.
            _ = conn.sendall(b"\xab" * RESPONSE_SIZE)
        finally:
            conn.close()
    except OSError as e:
        log.error("Listener on TCP/%d failed: %s", DNS_PORT, e)
        ready.set()
    finally:
        server.close()


@register_code_rta(
    id="a54b0408-e142-47db-804f-17fdb6ee3222",
    name="linux_dns_server_overflow",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="11013227-0301-4a8c-b150-4db924484475",
            name="Abnormally Large DNS Response",
        )
    ],
    techniques=["T1210", "T1499", "T1499.004"],
)
def main() -> None:
    """Generate a TCP flow with destination.port=53 and destination.bytes >= 65,000 to emulate SigRed (CVE-2020-1350)."""
    if os.geteuid() != 0:
        log.error("Binding TCP/53 requires root or CAP_NET_BIND_SERVICE")
        return

    ready = threading.Event()
    server_thread = threading.Thread(target=_serve_large_response, args=(ready,), daemon=True)
    server_thread.start()

    if not ready.wait(timeout=5):
        log.error("Listener did not start in time")
        return

    time.sleep(0.2)

    log.info("Connecting to %s:%d to receive oversized DNS-shaped response", LOCALHOST, DNS_PORT)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)
    received = 0
    try:
        client.connect((LOCALHOST, DNS_PORT))
        while True:
            chunk = client.recv(8192)
            if not chunk:
                break
            received += len(chunk)
        log.info("Client received %d bytes from TCP/%d", received, DNS_PORT)
    except OSError as e:
        log.error("Client connection failed: %s", e)
    finally:
        client.close()

    server_thread.join(timeout=10)
