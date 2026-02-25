# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Accepted Default Telnet Port Connection
# RTA: accepted_default_telnet_port_connection.py
# Description: Creates a network flow that is accepted with destination port 23 (default telnet port).
#              Does not use the telnet protocol; only establishes a TCP connection to port 23.
#              All traffic is localhost-only (no external host).

import logging
import socket
import threading
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

TELNET_PORT = 23
LOCALHOST = "127.0.0.1"


def _run_listener():
    """Listen on localhost:23 and accept one connection."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((LOCALHOST, TELNET_PORT))
        server.listen(1)
        server.settimeout(10)
        conn, _ = server.accept()
        conn.close()
    finally:
        server.close()


@register_code_rta(
    id="a1b2c3d4-e5f6-4789-a012-34fde48994b0",
    name="accepted_default_telnet_port_connection",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    siem_rules=[
        RuleMetadata(
            id="34fde489-94b0-4500-a76f-b8a157cf9269",
            name="Accepted Default Telnet Port Connection",
        )
    ],
    techniques=["T1071"],
)
def main():
    """Establish an accepted TCP connection to localhost:23 (telnet port)."""
    log.info("Creating accepted network connection to port %s (telnet) on localhost", TELNET_PORT)
    server_thread = threading.Thread(target=_run_listener)
    server_thread.start()
    time.sleep(0.5)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((LOCALHOST, TELNET_PORT))
        log.info("Connection to %s:%s accepted", LOCALHOST, TELNET_PORT)
    finally:
        sock.close()
    server_thread.join(timeout=15)
