# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PostgreSQL COPY PROGRAM Command Execution
# RTA: network_postgresql_copy_program_command.py
# Description: Completes a minimal PostgreSQL startup exchange and submits a
#              simple-query message containing COPY ... TO PROGRAM. The local
#              protocol stub acknowledges the query but never executes it,
#              allowing Network Packet Capture to decode the command safely.

import logging
import socket
import struct
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

POSTGRESQL_PORT = 5432
_PROTOCOL_VERSION_3 = 196608
_QUERY = b"COPY (SELECT 'cortado-rta') TO PROGRAM 'sh -c \"id >/tmp/cortado-rta\"'"


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("PostgreSQL peer closed the connection")
        data.extend(chunk)
    return bytes(data)


def _startup_message() -> bytes:
    parameters = b"user\x00rta_admin\x00database\x00postgres\x00application_name\x00cortado\x00\x00"
    body = struct.pack("!I", _PROTOCOL_VERSION_3) + parameters
    return struct.pack("!I", len(body) + 4) + body


def _message(message_type: bytes, payload: bytes) -> bytes:
    return message_type + struct.pack("!I", len(payload) + 4) + payload


def _recv_message(conn: socket.socket) -> tuple[bytes, bytes]:
    message_type = _recv_exact(conn, 1)
    length = struct.unpack("!I", _recv_exact(conn, 4))[0]
    if length < 4:
        raise ValueError("Invalid PostgreSQL message length")
    return message_type, _recv_exact(conn, length - 4)


def _serve_query(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    try:
        conn, addr = server.accept()
        log.debug("Accepted PostgreSQL connection from %s", addr)
        with conn:
            startup_length = struct.unpack("!I", _recv_exact(conn, 4))[0]
            startup = _recv_exact(conn, startup_length - 4)
            if not startup.startswith(struct.pack("!I", _PROTOCOL_VERSION_3)):
                raise ValueError("Unexpected PostgreSQL startup request")

            conn.sendall(_message(b"R", struct.pack("!I", 0)))
            conn.sendall(_message(b"S", b"server_version\x0016.0\x00"))
            conn.sendall(_message(b"S", b"client_encoding\x00UTF8\x00"))
            conn.sendall(_message(b"Z", b"I"))

            message_type, payload = _recv_message(conn)
            if message_type != b"Q" or b"COPY" not in payload or b"PROGRAM" not in payload:
                raise ValueError("Expected PostgreSQL COPY PROGRAM query")
            conn.sendall(_message(b"C", b"COPY 0\x00"))
            conn.sendall(_message(b"Z", b"I"))
    except (ConnectionError, OSError, ValueError) as e:
        log.error("PostgreSQL server error: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="014016f0-43f9-45bb-9445-e24507f1f91e",
    name="network_postgresql_copy_program_command",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="8ab64631-17ee-46b9-9800-9acacbeee1b3",
            name="PostgreSQL COPY PROGRAM Command Execution",
        )
    ],
    techniques=["T1059.004"],
)
def main() -> None:
    """Send a PostgreSQL COPY ... TO PROGRAM simple query."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", POSTGRESQL_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", POSTGRESQL_PORT, e)
        server.close()
        return
    server.listen(1)

    ready = threading.Event()
    thread = threading.Thread(target=_serve_query, args=(server, ready), daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        log.error("PostgreSQL listener did not start in time")
        server.close()
        return

    time.sleep(0.1)
    host_ip = get_host_ip()
    log.info("Sending PostgreSQL COPY PROGRAM query to %s:%d", host_ip, POSTGRESQL_PORT)
    try:
        with socket.create_connection((host_ip, POSTGRESQL_PORT), timeout=5) as conn:
            conn.sendall(_startup_message())
            while True:
                message_type, _ = _recv_message(conn)
                if message_type == b"Z":
                    break

            conn.sendall(_message(b"Q", _QUERY + b"\x00"))
            while True:
                message_type, _ = _recv_message(conn)
                if message_type == b"Z":
                    break
            log.info("PostgreSQL COPY PROGRAM transaction completed")
    except (ConnectionError, OSError, ValueError) as e:
        log.error("PostgreSQL client error: %s", e)

    thread.join(timeout=5)
