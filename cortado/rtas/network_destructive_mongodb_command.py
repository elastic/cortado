# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Destructive MongoDB Command
# RTA: network_destructive_mongodb_command.py
# Description: Sends a legacy MongoDB OP_QUERY command for
#              {"dropDatabase": 1} to the rta_victim.$cmd namespace and returns
#              a valid OP_REPLY. Packetbeat recognizes database commands carried
#              by OP_QUERY and publishes method=dropDatabase, satisfying the
#              rule's exact method branch without requiring MongoDB or deleting
#              any data.

import logging
import socket
import struct
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

MONGODB_PORT = 27017
_OP_REPLY = 1
_OP_QUERY = 2004


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("MongoDB peer closed the connection")
        data.extend(chunk)
    return bytes(data)


def _bson_document(elements: bytes) -> bytes:
    return struct.pack("<i", len(elements) + 5) + elements + b"\x00"


def _bson_string(name: str, value: str) -> bytes:
    encoded = value.encode() + b"\x00"
    return b"\x02" + name.encode() + b"\x00" + struct.pack("<i", len(encoded)) + encoded


def _bson_double(name: str, value: float) -> bytes:
    return b"\x01" + name.encode() + b"\x00" + struct.pack("<d", value)


def _message(request_id: int, response_to: int, opcode: int, payload: bytes) -> bytes:
    header = struct.pack("<iiii", 16 + len(payload), request_id, response_to, opcode)
    return header + payload


def _drop_database_request(request_id: int) -> bytes:
    document = _bson_document(
        # Packetbeat's OP_QUERY command classifier expects command value 1 as
        # a BSON double when decoding into its generic command map.
        _bson_double("dropDatabase", 1.0) + _bson_string("comment", "cortado-rta"),
    )
    payload = struct.pack("<i", 0)  # flags
    payload += b"rta_victim.$cmd\x00"
    payload += struct.pack("<ii", 0, -1)  # numberToSkip, numberToReturn
    payload += document
    return _message(request_id, 0, _OP_QUERY, payload)


def _success_response(request_id: int) -> bytes:
    document = _bson_document(_bson_double("ok", 1.0))
    payload = struct.pack("<iqii", 0, 0, 0, 1)
    payload += document
    return _message(request_id + 1, request_id, _OP_REPLY, payload)


def _serve_request(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    try:
        conn, addr = server.accept()
        log.debug("Accepted MongoDB connection from %s", addr)
        with conn:
            header = _recv_exact(conn, 16)
            message_length, request_id, _, opcode = struct.unpack("<iiii", header)
            if opcode != _OP_QUERY or message_length < 40:
                raise ValueError("Unexpected MongoDB request")
            _ = _recv_exact(conn, message_length - 16)
            conn.sendall(_success_response(request_id))
    except (ConnectionError, OSError, ValueError) as e:
        log.error("MongoDB server error: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="9fe6e8cf-9b99-41ad-945b-fbb9307b699b",
    name="network_destructive_mongodb_command",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="0d8a33be-5595-400c-a677-c4474829ed55",
            name="Destructive MongoDB Command",
        )
    ],
    techniques=["T1485"],
)
def main() -> None:
    """Send one successful MongoDB dropDatabase OP_QUERY transaction."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", MONGODB_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", MONGODB_PORT, e)
        server.close()
        return
    server.listen(1)

    ready = threading.Event()
    thread = threading.Thread(target=_serve_request, args=(server, ready), daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        log.error("MongoDB listener did not start in time")
        server.close()
        return

    time.sleep(0.1)
    host_ip = get_host_ip()
    request_id = 0x43525444
    log.info("Sending MongoDB OP_QUERY dropDatabase command to %s:%d", host_ip, MONGODB_PORT)
    try:
        with socket.create_connection((host_ip, MONGODB_PORT), timeout=5) as conn:
            conn.sendall(_drop_database_request(request_id))
            header = _recv_exact(conn, 16)
            message_length = struct.unpack("<i", header[:4])[0]
            _ = _recv_exact(conn, message_length - 16)
            log.info("MongoDB destructive-command transaction completed")
    except (ConnectionError, OSError) as e:
        log.error("MongoDB client error: %s", e)

    thread.join(timeout=5)
