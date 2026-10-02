# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Transport selection and message framing for the STUN/TURN lab harness.

Backends by transport and Python version:

- udp: cleartext, standard library only
- tls: standard library `ssl` TLS-PSK on Python 3.13+ (`tls_stdlib`); python-mbedtls on Python 3.12
- dtls: python-mbedtls (`mbedtls_transport`), which only ships wheels up to CPython 3.12

Encrypted backends are imported lazily, so optional dependencies are only needed when those transports are used.
"""

import logging
import socket
import ssl
import sys
import time
from typing import Literal, Protocol, cast

from .codec import (
    BINDING_REQUEST,
    HEADER,
    MAX_MESSAGE_SIZE,
    SOFTWARE_CLEARTEXT,
    SOFTWARE_ENCRYPTED,
    ProtocolError,
    decode_message,
    expected_message_size,
)

log = logging.getLogger(__name__)

TransportName = Literal["udp", "tls", "dtls"]
TRANSPORTS: tuple[TransportName, ...] = ("udp", "tls", "dtls")

# STUN (RFC 8489) registered ports: 3478 for UDP/TCP, 5349 for STUN over TLS/DTLS
DEFAULT_PORTS: dict[TransportName, int] = {"udp": 3478, "tls": 5349, "dtls": 5349}

SOFTWARE_BY_TRANSPORT: dict[TransportName, bytes] = {
    "udp": SOFTWARE_CLEARTEXT,
    "tls": SOFTWARE_ENCRYPTED,
    "dtls": SOFTWARE_ENCRYPTED,
}

Address = tuple[str, int]

# Shared by the TLS/DTLS backends so peers on different Python versions interoperate
PSK_IDENTITY = "safe-research-client"
SERVER_HOSTNAME = "safe-research-server"
HANDSHAKE_TIMEOUT_SECS = 10.0
CONNECT_RETRY_DELAY_SECS = 1.0

# `ssl.HAS_PSK` and the PSK callbacks were added in Python 3.13
STDLIB_TLS_PSK = sys.version_info >= (3, 13) and bool(getattr(ssl, "HAS_PSK", False))


class MissingDependencyError(ImportError):
    """Raised when an optional dependency needed for the selected transport is not installed."""


class Connection(Protocol):
    """Subset of the socket API shared by `socket.socket`, `ssl.SSLSocket`, and `mbedtls.tls.TLSWrappedSocket`."""

    def recv(self, bufsize: int, /) -> bytes: ...

    def send(self, data: bytes, /) -> int: ...

    def sendall(self, data: bytes, /) -> None: ...

    def settimeout(self, value: float | None, /) -> None: ...

    def close(self) -> None: ...


class MessageChannel:
    """Preserve STUN message boundaries over a datagram (UDP/DTLS) or stream (TLS) connection."""

    def __init__(self, connection: Connection, stream: bool, pending: list[bytes] | None = None):
        self.connection = connection
        self.stream = stream
        self._pending = list(pending or [])
        self._stream_buffer = bytearray()

    def send(self, message: bytes) -> None:
        """Send one complete STUN/TURN message."""
        if len(message) > MAX_MESSAGE_SIZE:
            raise ProtocolError("message exceeds the lab size limit")
        if self.stream:
            self.connection.sendall(message)
            return
        sent = self.connection.send(message)
        if sent != len(message):
            raise OSError("datagram was not sent atomically")

    def receive(self, timeout: float) -> bytes | None:
        """Receive one complete STUN/TURN message, or return `None` if nothing arrived within `timeout` seconds."""
        if self._pending:
            return self._pending.pop(0)
        self.connection.settimeout(max(timeout, 0.01))
        try:
            if not self.stream:
                data = self.connection.recv(MAX_MESSAGE_SIZE)
                if not data:
                    raise ConnectionError("peer closed the session")
                return bytes(data)
            return self._receive_from_stream()
        except TimeoutError:
            return None

    def _receive_from_stream(self) -> bytes:
        # A timeout may interrupt a partially received message; the buffer is kept for the next call
        while len(self._stream_buffer) < HEADER.size:
            self._read_stream_chunk()
        try:
            total = expected_message_size(bytes(self._stream_buffer[: HEADER.size]))
        except ProtocolError as exc:
            self._stream_buffer.clear()
            raise ConnectionError("invalid stream framing") from exc
        while len(self._stream_buffer) < total:
            self._read_stream_chunk()
        message = bytes(self._stream_buffer[:total])
        del self._stream_buffer[:total]
        return message

    def _read_stream_chunk(self) -> None:
        chunk = self.connection.recv(MAX_MESSAGE_SIZE)
        if not chunk:
            raise ConnectionError("peer closed the session")
        self._stream_buffer.extend(chunk)

    def close(self) -> None:
        self.connection.close()


class Listener(Protocol):
    """A bound server endpoint that accepts exactly one lab client."""

    @property
    def address(self) -> Address: ...

    def accept(self, timeout: float) -> tuple[MessageChannel, Address]: ...

    def close(self) -> None: ...


class UdpListener:
    """Cleartext UDP listener that locks onto the first peer sending a STUN Binding request."""

    def __init__(self, bind: Address):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(bind)

    @property
    def address(self) -> Address:
        return cast(Address, self._sock.getsockname())

    def accept(self, timeout: float) -> tuple[MessageChannel, Address]:
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0:
            self._sock.settimeout(remaining)
            try:
                datagram, peer = self._sock.recvfrom(MAX_MESSAGE_SIZE)
            except TimeoutError:
                break
            try:
                if decode_message(datagram).message_type != BINDING_REQUEST:
                    raise ProtocolError("first datagram is not a Binding request")
            except ProtocolError as exc:
                log.debug(f"Ignoring datagram from {peer}: {exc}")
                continue
            # A connected UDP socket only receives datagrams from this peer from now on
            self._sock.connect(peer)
            return MessageChannel(self._sock, stream=False, pending=[datagram]), cast(Address, peer)
        raise TimeoutError("no client registered before the deadline")

    def close(self) -> None:
        self._sock.close()


def open_listener(transport: TransportName, bind: Address, secret: bytes) -> Listener:
    """Bind a server listener for the selected transport."""
    if transport == "udp":
        return UdpListener(bind)
    if sys.version_info >= (3, 13) and transport == "tls" and STDLIB_TLS_PSK:
        from .tls_stdlib import TlsListener

        return TlsListener(bind, secret)

    if sys.version_info >= (3, 13):
        raise _mbedtls_unavailable(transport)
    try:
        from .mbedtls_transport import SecureListener
    except ImportError as exc:
        raise _mbedtls_unavailable(transport) from exc
    return SecureListener(transport, bind, secret)


def connect(transport: TransportName, address: Address, secret: bytes, timeout: float) -> MessageChannel:
    """Connect to a lab server, retrying encrypted handshakes until `timeout` seconds pass."""
    if transport == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(address)
        return MessageChannel(sock, stream=False)
    if sys.version_info >= (3, 13) and transport == "tls" and STDLIB_TLS_PSK:
        from .tls_stdlib import connect_tls

        return connect_tls(address, secret, timeout)

    if sys.version_info >= (3, 13):
        raise _mbedtls_unavailable(transport)
    try:
        from .mbedtls_transport import connect_secure
    except ImportError as exc:
        raise _mbedtls_unavailable(transport) from exc
    return connect_secure(transport, address, secret, timeout)


def _mbedtls_unavailable(transport: TransportName) -> MissingDependencyError:
    if sys.version_info >= (3, 13):
        return MissingDependencyError(
            f"The `{transport}` transport requires python-mbedtls, which only supports Python 3.12. "
            "Run this role with Python 3.12 and `pip install python-mbedtls` (or the `cortado[protocols]` extra)."
        )
    return MissingDependencyError(
        f"The `{transport}` transport requires the optional `python-mbedtls` package on Python 3.12. "
        "Install it with `pip install python-mbedtls` or the `cortado[protocols]` extra"
        + (", or use Python 3.13+ for TLS." if transport == "tls" else ".")
    )
