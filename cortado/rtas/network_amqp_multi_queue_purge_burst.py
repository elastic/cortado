# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Successful AMQP Multi-Queue Purge Burst
# RTA: network_amqp_multi_queue_purge_burst.py
# Description: Performs a minimal AMQP 0-9-1 connection/channel handshake and
#              sends successful queue.purge transactions for three distinct
#              queue names. The local broker stub returns queue.purge-ok for
#              each request but does not host queues or delete messages.

import logging
import socket
import struct
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

AMQP_PORT = 5672
QUEUE_NAMES = ("rta.orders", "rta.payments", "rta.notifications")

_PROTOCOL_HEADER = b"AMQP\x00\x00\x09\x01"
_FRAME_METHOD = 1
_FRAME_END = 0xCE

_CLASS_CONNECTION = 10
_CLASS_CHANNEL = 20
_CLASS_QUEUE = 50

_METHOD_CONNECTION_START = 10
_METHOD_CONNECTION_START_OK = 11
_METHOD_CONNECTION_TUNE = 30
_METHOD_CONNECTION_TUNE_OK = 31
_METHOD_CONNECTION_OPEN = 40
_METHOD_CONNECTION_OPEN_OK = 41
_METHOD_CHANNEL_OPEN = 10
_METHOD_CHANNEL_OPEN_OK = 11
_METHOD_QUEUE_PURGE = 30
_METHOD_QUEUE_PURGE_OK = 31


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("AMQP peer closed the connection")
        data.extend(chunk)
    return bytes(data)


def _short_string(value: str) -> bytes:
    encoded = value.encode()
    if len(encoded) > 255:
        raise ValueError("AMQP short string exceeds 255 bytes")
    return bytes((len(encoded),)) + encoded


def _long_string(value: bytes) -> bytes:
    return struct.pack("!I", len(value)) + value


def _frame(frame_type: int, channel: int, payload: bytes) -> bytes:
    return struct.pack("!BHI", frame_type, channel, len(payload)) + payload + bytes((_FRAME_END,))


def _method_frame(channel: int, class_id: int, method_id: int, arguments: bytes = b"") -> bytes:
    return _frame(_FRAME_METHOD, channel, struct.pack("!HH", class_id, method_id) + arguments)


def _recv_frame(conn: socket.socket) -> tuple[int, int, bytes]:
    frame_type, channel, size = struct.unpack("!BHI", _recv_exact(conn, 7))
    payload = _recv_exact(conn, size)
    if _recv_exact(conn, 1)[0] != _FRAME_END:
        raise ValueError("Invalid AMQP frame terminator")
    return frame_type, channel, payload


def _connection_start() -> bytes:
    arguments = b"\x00\x09"
    arguments += struct.pack("!I", 0)
    arguments += _long_string(b"PLAIN")
    arguments += _long_string(b"en_US")
    return _method_frame(0, _CLASS_CONNECTION, _METHOD_CONNECTION_START, arguments)


def _connection_start_ok() -> bytes:
    arguments = struct.pack("!I", 0)
    arguments += _short_string("PLAIN")
    arguments += _long_string(b"\x00guest\x00guest")
    arguments += _short_string("en_US")
    return _method_frame(0, _CLASS_CONNECTION, _METHOD_CONNECTION_START_OK, arguments)


def _connection_tune(method_id: int) -> bytes:
    return _method_frame(0, _CLASS_CONNECTION, method_id, struct.pack("!HIH", 0, 131072, 0))


def _queue_purge(queue_name: str) -> bytes:
    arguments = struct.pack("!H", 0)
    arguments += _short_string(queue_name)
    arguments += b"\x00"  # no-wait=false, so Packetbeat observes purge-ok
    return _method_frame(1, _CLASS_QUEUE, _METHOD_QUEUE_PURGE, arguments)


def _expect_method(conn: socket.socket, class_id: int, method_id: int) -> bytes:
    frame_type, _, payload = _recv_frame(conn)
    if frame_type != _FRAME_METHOD or payload[:4] != struct.pack("!HH", class_id, method_id):
        raise ValueError(f"Expected AMQP method {class_id}.{method_id}")
    return payload[4:]


def _purged_queue(arguments: bytes) -> str:
    if len(arguments) < 4:
        raise ValueError("Truncated AMQP queue.purge arguments")
    queue_length = arguments[2]
    queue_end = 3 + queue_length
    if queue_end >= len(arguments):
        raise ValueError("Truncated AMQP queue name")
    return arguments[3:queue_end].decode()


def _serve_purges(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    try:
        conn, addr = server.accept()
        log.debug("Accepted AMQP connection from %s", addr)
        with conn:
            if _recv_exact(conn, len(_PROTOCOL_HEADER)) != _PROTOCOL_HEADER:
                raise ValueError("Unexpected AMQP protocol header")
            conn.sendall(_connection_start())
            _ = _expect_method(conn, _CLASS_CONNECTION, _METHOD_CONNECTION_START_OK)

            conn.sendall(_connection_tune(_METHOD_CONNECTION_TUNE))
            _ = _expect_method(conn, _CLASS_CONNECTION, _METHOD_CONNECTION_TUNE_OK)
            _ = _expect_method(conn, _CLASS_CONNECTION, _METHOD_CONNECTION_OPEN)
            conn.sendall(
                _method_frame(
                    0,
                    _CLASS_CONNECTION,
                    _METHOD_CONNECTION_OPEN_OK,
                    _short_string(""),
                )
            )

            _ = _expect_method(conn, _CLASS_CHANNEL, _METHOD_CHANNEL_OPEN)
            conn.sendall(
                _method_frame(
                    1,
                    _CLASS_CHANNEL,
                    _METHOD_CHANNEL_OPEN_OK,
                    _long_string(b""),
                )
            )

            for expected_queue in QUEUE_NAMES:
                arguments = _expect_method(conn, _CLASS_QUEUE, _METHOD_QUEUE_PURGE)
                observed_queue = _purged_queue(arguments)
                if observed_queue != expected_queue:
                    raise ValueError(f"Expected queue {expected_queue}, received {observed_queue}")
                conn.sendall(
                    _method_frame(
                        1,
                        _CLASS_QUEUE,
                        _METHOD_QUEUE_PURGE_OK,
                        struct.pack("!I", 0),
                    )
                )
    except (ConnectionError, OSError, UnicodeDecodeError, ValueError) as e:
        log.error("AMQP broker stub error: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="8ed97327-2fe4-4730-b343-a94c85178d87",
    name="network_amqp_multi_queue_purge_burst",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="286614ee-8b72-4ea5-a22d-e0d2ae59d0a9",
            name="Successful AMQP Multi-Queue Purge Burst",
        )
    ],
    techniques=["T1485"],
)
def main() -> None:
    """Send successful AMQP queue.purge transactions for three queues."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", AMQP_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d: %s", AMQP_PORT, e)
        server.close()
        return
    server.listen(1)

    ready = threading.Event()
    thread = threading.Thread(target=_serve_purges, args=(server, ready), daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        log.error("AMQP listener did not start in time")
        server.close()
        return

    time.sleep(0.1)
    host_ip = get_host_ip()
    log.info("Sending AMQP queue.purge burst to %s:%d", host_ip, AMQP_PORT)
    try:
        with socket.create_connection((host_ip, AMQP_PORT), timeout=5) as conn:
            conn.sendall(_PROTOCOL_HEADER)
            _ = _expect_method(conn, _CLASS_CONNECTION, _METHOD_CONNECTION_START)
            conn.sendall(_connection_start_ok())
            _ = _expect_method(conn, _CLASS_CONNECTION, _METHOD_CONNECTION_TUNE)
            conn.sendall(_connection_tune(_METHOD_CONNECTION_TUNE_OK))
            conn.sendall(
                _method_frame(
                    0,
                    _CLASS_CONNECTION,
                    _METHOD_CONNECTION_OPEN,
                    _short_string("/") + _short_string("") + b"\x00",
                )
            )
            _ = _expect_method(conn, _CLASS_CONNECTION, _METHOD_CONNECTION_OPEN_OK)

            conn.sendall(
                _method_frame(
                    1,
                    _CLASS_CHANNEL,
                    _METHOD_CHANNEL_OPEN,
                    _short_string(""),
                )
            )
            _ = _expect_method(conn, _CLASS_CHANNEL, _METHOD_CHANNEL_OPEN_OK)

            for queue_name in QUEUE_NAMES:
                conn.sendall(_queue_purge(queue_name))
                _ = _expect_method(conn, _CLASS_QUEUE, _METHOD_QUEUE_PURGE_OK)
                log.info("AMQP queue.purge-ok received for %s", queue_name)
    except (ConnectionError, OSError, ValueError) as e:
        log.error("AMQP client error: %s", e)

    thread.join(timeout=5)
