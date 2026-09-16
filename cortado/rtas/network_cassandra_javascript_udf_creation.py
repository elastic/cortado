# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Cassandra JavaScript UDF Creation
# RTA: network_cassandra_javascript_udf_creation.py
# Description: Completes a Cassandra native-protocol startup exchange and sends
#              a QUERY frame containing CREATE FUNCTION ... LANGUAGE JAVASCRIPT.
#              A local protocol stub returns a VOID result and never runs the
#              CQL, safely exposing the query text to Network Packet Capture.

import logging
import socket
import struct
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

CASSANDRA_PORT = 9042

_REQUEST_VERSION = 0x04
_RESPONSE_VERSION = 0x84
_OPCODE_STARTUP = 0x01
_OPCODE_READY = 0x02
_OPCODE_QUERY = 0x07
_OPCODE_RESULT = 0x08
_RESULT_VOID = 0x00000001
_CONSISTENCY_ONE = 0x0001

_QUERY = (
    "CREATE FUNCTION rta.exec(command text) "
    "RETURNS NULL ON NULL INPUT RETURNS text "
    "LANGUAGE JAVASCRIPT AS 'java.lang.Runtime.getRuntime().exec(command); return command;'"
)


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Cassandra peer closed the connection")
        data.extend(chunk)
    return bytes(data)


def _short_string(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack("!H", len(encoded)) + encoded


def _frame(version: int, stream: int, opcode: int, body: bytes) -> bytes:
    return struct.pack("!BBhBI", version, 0, stream, opcode, len(body)) + body


def _recv_frame(conn: socket.socket) -> tuple[int, int, int, bytes]:
    header = _recv_exact(conn, 9)
    version, _, stream, opcode, length = struct.unpack("!BBhBI", header)
    return version, stream, opcode, _recv_exact(conn, length)


def _startup_frame() -> bytes:
    body = struct.pack("!H", 1)
    body += _short_string("CQL_VERSION")
    body += _short_string("3.0.0")
    return _frame(_REQUEST_VERSION, 0, _OPCODE_STARTUP, body)


def _query_frame() -> bytes:
    encoded = _QUERY.encode()
    body = struct.pack("!I", len(encoded)) + encoded
    body += struct.pack("!HB", _CONSISTENCY_ONE, 0)
    return _frame(_REQUEST_VERSION, 1, _OPCODE_QUERY, body)


def _serve_query(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    try:
        conn, addr = server.accept()
        log.debug("Accepted Cassandra connection from %s", addr)
        with conn:
            version, stream, opcode, _ = _recv_frame(conn)
            if version != _REQUEST_VERSION or opcode != _OPCODE_STARTUP:
                raise ValueError("Expected Cassandra STARTUP frame")
            conn.sendall(_frame(_RESPONSE_VERSION, stream, _OPCODE_READY, b""))

            version, stream, opcode, body = _recv_frame(conn)
            if version != _REQUEST_VERSION or opcode != _OPCODE_QUERY:
                raise ValueError("Expected Cassandra QUERY frame")
            if b"CREATE FUNCTION" not in body or b"LANGUAGE JAVASCRIPT" not in body:
                raise ValueError("Expected Cassandra JavaScript UDF query")
            conn.sendall(_frame(_RESPONSE_VERSION, stream, _OPCODE_RESULT, struct.pack("!I", _RESULT_VOID)))
    except (ConnectionError, OSError, ValueError) as e:
        log.error("Cassandra server error: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="81715e08-b070-4f23-a407-8b005f00a143",
    name="network_cassandra_javascript_udf_creation",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="b3e2c2ad-9a81-4638-bf12-7ca2feed66a2",
            name="Cassandra JavaScript UDF Creation",
        )
    ],
    techniques=["T1059.007"],
)
def main() -> None:
    """Send a Cassandra CREATE FUNCTION ... LANGUAGE JAVASCRIPT query."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", CASSANDRA_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", CASSANDRA_PORT, e)
        server.close()
        return
    server.listen(1)

    ready = threading.Event()
    thread = threading.Thread(target=_serve_query, args=(server, ready), daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        log.error("Cassandra listener did not start in time")
        server.close()
        return

    time.sleep(0.1)
    host_ip = get_host_ip()
    log.info("Sending Cassandra JavaScript UDF query to %s:%d", host_ip, CASSANDRA_PORT)
    try:
        with socket.create_connection((host_ip, CASSANDRA_PORT), timeout=5) as conn:
            conn.sendall(_startup_frame())
            _, _, opcode, _ = _recv_frame(conn)
            if opcode != _OPCODE_READY:
                raise ValueError("Cassandra server did not become ready")

            conn.sendall(_query_frame())
            _, _, opcode, _ = _recv_frame(conn)
            if opcode != _OPCODE_RESULT:
                raise ValueError("Cassandra server did not return a result")
            log.info("Cassandra JavaScript UDF transaction completed")
    except (ConnectionError, OSError, ValueError) as e:
        log.error("Cassandra client error: %s", e)

    thread.join(timeout=5)
