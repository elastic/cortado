# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""TLS-over-TCP transport with PSK authentication using the standard library `ssl` module (Python 3.13+).

Negotiates TLS 1.2 PSK cipher suites, like the python-mbedtls implementation, so hosts on different Python
versions interoperate and produce comparable handshakes. Import this module only through `transports`.
"""

import sys

# Everything below is unreachable for type checkers on older Python versions, which lack the TLS-PSK API
if sys.version_info < (3, 13):
    raise ImportError("TLS-PSK support in the `ssl` module requires Python 3.13+")

import logging  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402
import time  # noqa: E402
from contextlib import suppress  # noqa: E402
from typing import cast  # noqa: E402

from .transports import (  # noqa: E402
    CONNECT_RETRY_DELAY_SECS,
    HANDSHAKE_TIMEOUT_SECS,
    PSK_IDENTITY,
    SERVER_HOSTNAME,
    Address,
    MessageChannel,
)

log = logging.getLogger(__name__)

PSK_CIPHERS = "PSK"


def _configure(context: ssl.SSLContext) -> ssl.SSLContext:
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # TLS 1.3 external PSKs work differently; TLS 1.2 keeps parity with the python-mbedtls peers
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(PSK_CIPHERS)
    return context


def _client_context(secret: bytes) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Peers authenticate with the PSK; there are no certificates
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_psk_client_callback(lambda _hint: (PSK_IDENTITY, secret))
    return _configure(context)


def _server_context(secret: bytes) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # An empty key rejects unknown identities
    context.set_psk_server_callback(lambda identity: secret if identity == PSK_IDENTITY else b"")
    return _configure(context)


def _handshake_or_close(connection: ssl.SSLSocket) -> None:
    # Close right away on failure so the peer sees the rejection instead of waiting for its timeout
    try:
        connection.do_handshake()
    except BaseException:
        with suppress(OSError):
            connection.close()
        raise


def connect_tls(address: Address, secret: bytes, timeout: float) -> MessageChannel:
    """Connect and complete a TLS-PSK handshake, retrying until the server is reachable or `timeout` passes."""
    deadline = time.monotonic() + timeout
    context = _client_context(secret)
    last_error: Exception | None = None

    while (remaining := deadline - time.monotonic()) > 0:
        try:
            raw = socket.create_connection(address, timeout=min(remaining, HANDSHAKE_TIMEOUT_SECS))
        except OSError as exc:
            # The server isn't reachable (yet): refused, unreachable, or timed out
            last_error = exc
            log.debug(f"TLS connection to {address} failed, retrying: {exc!r}")
            time.sleep(min(CONNECT_RETRY_DELAY_SECS, max(deadline - time.monotonic(), 0)))
            continue

        connection = context.wrap_socket(raw, server_hostname=SERVER_HOSTNAME, do_handshake_on_connect=False)
        try:
            _handshake_or_close(connection)
        except OSError as exc:
            # The server accepted the connection but the handshake failed, most likely because the PSKs differ
            raise ConnectionError(
                f"TLS handshake with {address} failed ({exc!r}); check that both roles use the same secret"
            ) from exc
        return MessageChannel(connection, stream=True)

    raise TimeoutError(
        f"could not establish a TLS session with {address} ({last_error!r}); "
        "check that the server role is running and reachable and that both roles use the same secret"
    )


class TlsListener:
    """TLS-PSK listener that completes a handshake with exactly one lab client."""

    def __init__(self, bind: Address, secret: bytes):
        self._context = _server_context(secret)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(bind)
        self._sock.listen(1)

    @property
    def address(self) -> Address:
        return cast(Address, self._sock.getsockname())

    def accept(self, timeout: float) -> tuple[MessageChannel, Address]:
        self._sock.settimeout(timeout)
        raw, peer = self._sock.accept()
        raw.settimeout(HANDSHAKE_TIMEOUT_SECS)
        connection = self._context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        _handshake_or_close(connection)
        return MessageChannel(connection, stream=True), cast(Address, peer)

    def close(self) -> None:
        with suppress(OSError):
            self._sock.close()
