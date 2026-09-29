# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: MySQL User-Defined Function Injection
# RTA: network_mysql_udf_injection.py
# Description: Performs a minimal MySQL handshake and sends a COM_QUERY packet
#              containing `CREATE FUNCTION ... SONAME`. A local protocol stub
#              returns successful MySQL responses, so Network Packet Capture
#              publishes the query without requiring MySQL, a shared library,
#              or any database modification.

import logging
import socket
import struct
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

MYSQL_PORT = 3306

_CLIENT_LONG_PASSWORD = 0x00000001
_CLIENT_LONG_FLAG = 0x00000004
_CLIENT_PROTOCOL_41 = 0x00000200
_CLIENT_TRANSACTIONS = 0x00002000
_CLIENT_SECURE_CONNECTION = 0x00008000
_CLIENT_MULTI_RESULTS = 0x00020000
_CLIENT_PLUGIN_AUTH = 0x00080000
_CAPABILITIES = (
    _CLIENT_LONG_PASSWORD
    | _CLIENT_LONG_FLAG
    | _CLIENT_PROTOCOL_41
    | _CLIENT_TRANSACTIONS
    | _CLIENT_SECURE_CONNECTION
    | _CLIENT_MULTI_RESULTS
    | _CLIENT_PLUGIN_AUTH
)

_QUERY = b"CREATE FUNCTION sys_exec RETURNS STRING SONAME 'lib_mysqludf_sys.so'"


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("MySQL peer closed the connection")
        data.extend(chunk)
    return bytes(data)


def _packet(payload: bytes, sequence: int) -> bytes:
    length = len(payload)
    return bytes((length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, sequence)) + payload


def _recv_packet(conn: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(conn, 4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    return header[3], _recv_exact(conn, length)


def _server_greeting() -> bytes:
    scramble = b"cortado-rta-auth-see"  # 20-byte MySQL authentication seed
    payload = b"\x0a8.0.36-cortado\x00"
    payload += struct.pack("<I", 1337)
    payload += scramble[:8] + b"\x00"
    payload += struct.pack("<H", _CAPABILITIES & 0xFFFF)
    payload += b"\x21"
    payload += struct.pack("<H", 0x0002)
    payload += struct.pack("<H", (_CAPABILITIES >> 16) & 0xFFFF)
    payload += b"\x15"
    payload += b"\x00" * 10
    payload += scramble[8:] + b"\x00"
    payload += b"mysql_native_password\x00"
    return _packet(payload, 0)


def _client_handshake_response() -> bytes:
    payload = struct.pack("<IIB", _CAPABILITIES, 16 * 1024 * 1024, 0x21)
    payload += b"\x00" * 23
    payload += b"rta_admin\x00"
    payload += b"\x00"  # zero-length authentication response
    payload += b"mysql_native_password\x00"
    return _packet(payload, 1)


def _ok_packet(sequence: int) -> bytes:
    return _packet(b"\x00\x00\x00\x02\x00\x00\x00", sequence)


def _serve_query(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    try:
        conn, addr = server.accept()
        log.debug("Accepted MySQL connection from %s", addr)
        with conn:
            conn.sendall(_server_greeting())
            _, auth = _recv_packet(conn)
            if not auth:
                raise ValueError("Empty MySQL handshake response")
            conn.sendall(_ok_packet(2))

            sequence, query = _recv_packet(conn)
            if sequence != 0 or not query.startswith(b"\x03"):
                raise ValueError("Expected MySQL COM_QUERY")
            conn.sendall(_ok_packet(1))
    except (ConnectionError, OSError, ValueError) as e:
        log.error("MySQL server error: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="242ac8b7-98cc-4ad5-baf2-c7fed991ed68",
    name="network_mysql_udf_injection",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="c375532d-069d-41e0-af70-8ca032eb58f5",
            name="MySQL User-Defined Function Injection",
        )
    ],
    techniques=["T1505.001"],
)
def main() -> None:
    """Send a MySQL CREATE FUNCTION ... SONAME query."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", MYSQL_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", MYSQL_PORT, e)
        server.close()
        return
    server.listen(1)

    ready = threading.Event()
    thread = threading.Thread(target=_serve_query, args=(server, ready), daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        log.error("MySQL listener did not start in time")
        server.close()
        return

    time.sleep(0.1)
    host_ip = get_host_ip()
    log.info("Sending MySQL UDF injection query to %s:%d", host_ip, MYSQL_PORT)
    try:
        with socket.create_connection((host_ip, MYSQL_PORT), timeout=5) as conn:
            _, greeting = _recv_packet(conn)
            if not greeting.startswith(b"\x0a"):
                raise ValueError("Unexpected MySQL greeting")
            conn.sendall(_client_handshake_response())
            _, _ = _recv_packet(conn)
            conn.sendall(_packet(b"\x03" + _QUERY, 0))
            _, _ = _recv_packet(conn)
            log.info("MySQL CREATE FUNCTION ... SONAME transaction completed")
    except (ConnectionError, OSError, ValueError) as e:
        log.error("MySQL client error: %s", e)

    thread.join(timeout=5)
