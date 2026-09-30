# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""DTLS-over-UDP (and, on Python 3.12, TLS-over-TCP) transports with PSK authentication using python-mbedtls.

Requires the optional `python-mbedtls` package, which only ships wheels up to CPython 3.12. On Python 3.13+ TLS
uses the standard library instead (`tls_stdlib`), and DTLS isn't available. Import this module only through
`transports`, which reports a clear error when it can't be used.
"""

import sys

# Everything below is unreachable for type checkers on newer Python versions, where python-mbedtls can't be installed
if sys.version_info >= (3, 13):
    raise ImportError("python-mbedtls only supports Python 3.12 and older")

import logging  # noqa: E402
import socket  # noqa: E402
import time  # noqa: E402
from contextlib import suppress  # noqa: E402
from typing import Literal, cast  # noqa: E402

from mbedtls.exceptions import TLSError  # noqa: E402
from mbedtls.tls import (  # noqa: E402
    ClientContext,
    DTLSConfiguration,
    DTLSVersion,
    HelloVerifyRequest,
    ServerContext,
    TLSConfiguration,
    TLSVersion,
    TLSWrappedSocket,
    WantReadError,
)

from .transports import (  # noqa: E402
    CONNECT_RETRY_DELAY_SECS,
    HANDSHAKE_TIMEOUT_SECS,
    PSK_IDENTITY,
    SERVER_HOSTNAME,
    Address,
    MessageChannel,
)

log = logging.getLogger(__name__)

SecureTransportName = Literal["tls", "dtls"]


class _EofRaisingSocket(socket.socket):
    """TCP socket whose `recv` raises on EOF.

    `TLSWrappedSocket.do_handshake` feeds an empty read back into the handshake and reads again, so a peer that
    closes the connection mid-handshake (e.g. after a PSK mismatch) would make it spin forever, ignoring timeouts.
    """

    def recv(self, bufsize: int, flags: int = 0, /) -> bytes:
        data = super().recv(bufsize, flags)
        if not data and self.type == socket.SOCK_STREAM:
            raise ConnectionResetError("peer closed the connection")
        return data


class _TlsConnection:
    """Adapt `TLSWrappedSocket` to the `Connection` protocol, retrying reads of partial TLS records."""

    def __init__(self, wrapped: TLSWrappedSocket):
        self._wrapped = wrapped

    def recv(self, bufsize: int, /) -> bytes:
        while True:
            try:
                return self._wrapped.recv(bufsize)
            except WantReadError:
                continue

    def send(self, data: bytes, /) -> int:
        return self._wrapped.send(data)

    def sendall(self, data: bytes, /) -> None:
        self._wrapped.sendall(data)

    def settimeout(self, value: float | None, /) -> None:
        self._wrapped.settimeout(value)

    def close(self) -> None:
        with suppress(OSError, TLSError):
            self._wrapped.close()


def _client_configuration(transport: SecureTransportName, secret: bytes) -> TLSConfiguration | DTLSConfiguration:
    psk = (PSK_IDENTITY, secret)
    if transport == "tls":
        return TLSConfiguration(
            pre_shared_key=psk,
            validate_certificates=False,
            lowest_supported_version=TLSVersion.TLSv1_2,
        )
    return DTLSConfiguration(
        pre_shared_key=psk,
        validate_certificates=False,
        lowest_supported_version=DTLSVersion.DTLSv1_2,
        anti_replay=True,
    )


def _server_configuration(transport: SecureTransportName, secret: bytes) -> TLSConfiguration | DTLSConfiguration:
    psk_store = {PSK_IDENTITY: secret}
    if transport == "tls":
        return TLSConfiguration(
            pre_shared_key_store=psk_store,
            validate_certificates=False,
            lowest_supported_version=TLSVersion.TLSv1_2,
            read_timeout=HANDSHAKE_TIMEOUT_SECS,
        )
    return DTLSConfiguration(
        pre_shared_key_store=psk_store,
        validate_certificates=False,
        lowest_supported_version=DTLSVersion.DTLSv1_2,
        anti_replay=True,
        read_timeout=HANDSHAKE_TIMEOUT_SECS,
    )


def _socket_type(transport: SecureTransportName) -> socket.SocketKind:
    return socket.SOCK_STREAM if transport == "tls" else socket.SOCK_DGRAM


def connect_secure(
    transport: SecureTransportName, address: Address, secret: bytes, timeout: float
) -> MessageChannel:
    """Connect and complete a TLS/DTLS handshake, retrying until the server is reachable or `timeout` passes."""
    deadline = time.monotonic() + timeout
    context = ClientContext(_client_configuration(transport, secret))
    last_error: Exception | None = None

    while (remaining := deadline - time.monotonic()) > 0:
        wrapped = context.wrap_socket(_EofRaisingSocket(socket.AF_INET, _socket_type(transport)), SERVER_HOSTNAME)
        try:
            wrapped.settimeout(min(remaining, HANDSHAKE_TIMEOUT_SECS))
            wrapped.connect(address)
            wrapped.do_handshake()
            return MessageChannel(_TlsConnection(wrapped), stream=transport == "tls")
        except TLSError as exc:
            # The server answered but the handshake failed, most likely because the PSKs differ; retrying won't help
            with suppress(OSError, TLSError):
                wrapped.close()
            raise ConnectionError(
                f"{transport.upper()} handshake with {address} failed ({exc!r}); check that both roles use the same secret"
            ) from exc
        except ConnectionResetError as exc:
            with suppress(OSError, TLSError):
                wrapped.close()
            raise ConnectionError(
                f"{transport.upper()} server {address} closed the connection during the handshake; "
                "check that both roles use the same secret"
            ) from exc
        except OSError as exc:
            # The server isn't reachable (yet): refused, unreachable, or timed out
            last_error = exc
            with suppress(OSError, TLSError):
                wrapped.close()
            log.debug(f"{transport.upper()} connection to {address} failed, retrying: {exc!r}")
            time.sleep(min(CONNECT_RETRY_DELAY_SECS, max(deadline - time.monotonic(), 0)))

    raise TimeoutError(
        f"could not establish a {transport.upper()} session with {address} ({last_error!r}); "
        "check that the server role is running and reachable and that both roles use the same secret"
    )


def _handshake_or_close(connection: TLSWrappedSocket) -> None:
    # Close right away on failure so the peer sees the rejection instead of waiting for its timeout
    try:
        connection.do_handshake()
    except BaseException:
        with suppress(OSError, TLSError):
            connection.close()
        raise


class SecureListener:
    """TLS/DTLS listener that completes a PSK handshake with exactly one lab client."""

    def __init__(self, transport: SecureTransportName, bind: Address, secret: bytes):
        self.transport: SecureTransportName = transport
        self._context = ServerContext(_server_configuration(transport, secret))
        raw = socket.socket(socket.AF_INET, _socket_type(transport))
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(bind)
        self._tcp: socket.socket | None = None
        self._dtls: TLSWrappedSocket | None = None
        if transport == "tls":
            # TCP connections are accepted unwrapped, so each one can be wrapped as an `_EofRaisingSocket`
            raw.listen(1)
            self._tcp = raw
        else:
            self._dtls = self._context.wrap_socket(raw)

    @property
    def address(self) -> Address:
        sock = self._tcp or self._dtls
        assert sock is not None
        return cast(Address, sock.getsockname())

    def accept(self, timeout: float) -> tuple[MessageChannel, Address]:
        if self._tcp is not None:
            self._tcp.settimeout(timeout)
            raw, peer = self._tcp.accept()
            connection = self._context.wrap_socket(
                _EofRaisingSocket(raw.family, raw.type, raw.proto, fileno=raw.detach())
            )
            connection.settimeout(HANDSHAKE_TIMEOUT_SECS)
            _handshake_or_close(connection)
            return MessageChannel(_TlsConnection(connection), stream=True), cast(Address, peer)

        # DTLS: the first ClientHello is answered with a HelloVerifyRequest cookie exchange,
        # then the client retries on a new connection that completes the handshake
        assert self._dtls is not None
        self._dtls.settimeout(timeout)
        connection, peer = self._dtls.accept()
        connection.settimeout(HANDSHAKE_TIMEOUT_SECS)
        connection.setcookieparam(str(peer[0]).encode("ascii"))
        with suppress(HelloVerifyRequest):
            connection.do_handshake()
        previous, (connection, peer) = connection, connection.accept()
        previous.close()
        connection.settimeout(HANDSHAKE_TIMEOUT_SECS)
        connection.setcookieparam(str(peer[0]).encode("ascii"))
        _handshake_or_close(connection)
        return MessageChannel(_TlsConnection(connection), stream=False), cast(Address, peer)

    def close(self) -> None:
        with suppress(OSError, TLSError):
            if self._tcp is not None:
                self._tcp.close()
            if self._dtls is not None:
                self._dtls.close()
