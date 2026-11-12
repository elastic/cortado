# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Build and safely emit synthetic Cisco syslog events.

The destination Elastic Agent input determines ``data_stream.dataset``. These
messages must be sent to a Cisco ASA, Cisco Secure Firewall Threat Defense, or
Cisco ISE integration listener as appropriate; the sender cannot select the
dataset.

Message shapes follow the Cisco ASA, FTD, and ISE fixtures and ingest pipelines
at ``elastic/integrations@4c0916e8faf8172686249fa33308f1f9e8f077aa``.
"""

import ipaddress
import logging
import os
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

log = logging.getLogger(__name__)

DEFAULT_SYSLOG_HOST = "127.0.0.1"
DEFAULT_SYSLOG_PORT = 9514
SOCKET_TIMEOUT_SECONDS = 10.0

SyslogProtocol = Literal["udp", "tcp"]
SocketAddress = tuple[str, int] | tuple[str, int, int, int]
AddressInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, SocketAddress]


class SyslogConfigurationError(ValueError):
    """Raised when the syslog destination configuration is invalid or unsafe."""


class SyslogTransmissionError(RuntimeError):
    """Raised when a syslog message cannot be transmitted."""


@dataclass(frozen=True)
class SyslogConfig:
    """Validated runtime configuration for a syslog destination."""

    host: str
    port: int
    protocol: SyslogProtocol
    allow_remote: bool
    dry_run: bool


def _read_boolean(name: str) -> bool:
    value = os.environ.get(name, "0").strip()
    if value not in {"0", "1"}:
        raise SyslogConfigurationError(f"{name} must be either 0 or 1")
    return value == "1"


def config_from_environment() -> SyslogConfig:
    """Read and validate Cisco syslog sender environment variables."""
    host = os.environ.get("CORTADO_SYSLOG_HOST", DEFAULT_SYSLOG_HOST).strip()
    if not host:
        raise SyslogConfigurationError("CORTADO_SYSLOG_HOST must not be empty")
    if "\x00" in host or any(character.isspace() for character in host):
        raise SyslogConfigurationError("CORTADO_SYSLOG_HOST contains invalid characters")

    port_text = os.environ.get("CORTADO_SYSLOG_PORT", str(DEFAULT_SYSLOG_PORT)).strip()
    if not port_text.isascii() or not port_text.isdigit():
        raise SyslogConfigurationError("CORTADO_SYSLOG_PORT must be an integer between 1 and 65535")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise SyslogConfigurationError("CORTADO_SYSLOG_PORT must be between 1 and 65535")

    protocol_text = os.environ.get("CORTADO_SYSLOG_PROTOCOL", "udp").strip().lower()
    if protocol_text not in {"udp", "tcp"}:
        raise SyslogConfigurationError("CORTADO_SYSLOG_PROTOCOL must be udp or tcp")

    return SyslogConfig(
        host=host,
        port=port,
        protocol=cast(SyslogProtocol, protocol_text),
        allow_remote=_read_boolean("CORTADO_SYSLOG_ALLOW_REMOTE"),
        dry_run=_read_boolean("CORTADO_SYSLOG_DRY_RUN"),
    )


def _validate_config(config: SyslogConfig) -> None:
    if not config.host:
        raise SyslogConfigurationError("Syslog host must not be empty")
    if "\x00" in config.host or any(character.isspace() for character in config.host):
        raise SyslogConfigurationError("Syslog host contains invalid characters")
    if not 1 <= config.port <= 65535:
        raise SyslogConfigurationError("Syslog port must be between 1 and 65535")
    if config.protocol not in {"udp", "tcp"}:
        raise SyslogConfigurationError("Syslog protocol must be udp or tcp")


def _resolve_destination(config: SyslogConfig) -> list[AddressInfo]:
    socket_kind = socket.SOCK_DGRAM if config.protocol == "udp" else socket.SOCK_STREAM
    try:
        resolved = cast(
            list[AddressInfo],
            socket.getaddrinfo(
                config.host,
                config.port,
                family=socket.AF_UNSPEC,
                type=socket_kind,
            ),
        )
    except socket.gaierror as error:
        raise SyslogConfigurationError(f"Unable to resolve CORTADO_SYSLOG_HOST {config.host!r}: {error}") from error

    if not resolved:
        raise SyslogConfigurationError(f"CORTADO_SYSLOG_HOST {config.host!r} resolved to no addresses")

    destination_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _, _, _, _, socket_address in resolved:
        address_text = socket_address[0].split("%", maxsplit=1)[0]
        try:
            destination_ips.append(ipaddress.ip_address(address_text))
        except ValueError as error:
            raise SyslogConfigurationError(
                f"CORTADO_SYSLOG_HOST {config.host!r} resolved to invalid address {address_text!r}"
            ) from error

    if not config.allow_remote and any(not address.is_loopback for address in destination_ips):
        raise SyslogConfigurationError(
            "Refusing non-loopback syslog destination; set CORTADO_SYSLOG_ALLOW_REMOTE=1 to allow it"
        )
    return resolved


def _encode_messages(messages: Iterable[object]) -> tuple[bytes, ...]:
    encoded_messages: list[bytes] = []
    for message in messages:
        if not isinstance(message, str):
            raise TypeError("Syslog messages must be strings")
        if not message:
            raise ValueError("Syslog messages must not be empty")
        if "\r" in message or "\n" in message or "\x00" in message:
            raise ValueError("Syslog messages must not contain CR, LF, or NUL characters")
        encoded_messages.append(message.encode("utf-8"))
    if not encoded_messages:
        raise ValueError("At least one syslog message is required")
    return tuple(encoded_messages)


def send_syslog(messages: Iterable[str], config: SyslogConfig | None = None) -> None:
    """Send raw syslog messages using one datagram or one TCP line per event."""
    destination = config or config_from_environment()
    _validate_config(destination)
    encoded_messages = _encode_messages(messages)

    try:
        resolved = _resolve_destination(destination)
        family, socket_kind, protocol_number, _, socket_address = resolved[0]

        action = "Dry-running" if destination.dry_run else "Sending"
        log.info(
            "%s %d Cisco syslog message(s) via %s to %s:%d",
            action,
            len(encoded_messages),
            destination.protocol.upper(),
            destination.host,
            destination.port,
        )

        if destination.dry_run:
            for payload in encoded_messages:
                log.info("Dry-run Cisco syslog payload: %s", payload.decode("utf-8"))
            return

        with socket.socket(family, socket_kind, protocol_number) as syslog_socket:
            syslog_socket.settimeout(SOCKET_TIMEOUT_SECONDS)
            if destination.protocol == "udp":
                for payload in encoded_messages:
                    bytes_sent = syslog_socket.sendto(payload, socket_address)
                    if bytes_sent != len(payload):
                        raise SyslogTransmissionError(
                            f"UDP syslog transmission was incomplete: sent {bytes_sent} of {len(payload)} bytes"
                        )
            else:
                syslog_socket.connect(socket_address)
                for payload in encoded_messages:
                    syslog_socket.sendall(payload + b"\n")
    except SyslogConfigurationError:
        raise
    except (OSError, SyslogTransmissionError) as error:
        raise SyslogTransmissionError(
            f"Failed to send {len(encoded_messages)} Cisco syslog message(s) via "
            f"{destination.protocol.upper()} to {destination.host}:{destination.port}: {error}"
        ) from error

    log.info(
        "Sent %d Cisco syslog message(s) via %s to %s:%d",
        len(encoded_messages),
        destination.protocol.upper(),
        destination.host,
        destination.port,
    )


def build_asa_message(
    message_id: int,
    body: str,
    *,
    appliance: str,
    timestamp: datetime | None = None,
) -> str:
    """Build a Cisco ASA EMBLEM syslog message accepted by ASA and FTD inputs."""
    event_time = (timestamp or datetime.now(UTC)).astimezone(UTC)
    iso_timestamp = event_time.isoformat(timespec="seconds").replace("+00:00", "Z")
    return f"<181>{iso_timestamp} {appliance}: %ASA-5-{message_id}: {body}"


def build_ise_message(
    *,
    category: str,
    message_id: int,
    event_code: int,
    description: str,
    details: str,
    appliance: str = "ise-rta",
    timestamp: datetime | None = None,
) -> str:
    """Build a one-segment Cisco ISE syslog message from pinned fixture syntax."""
    event_time = (timestamp or datetime.now(UTC)).astimezone(UTC)
    outer_timestamp = event_time.strftime("%b %d %H:%M:%S")
    inner_timestamp = f"{event_time.strftime('%Y-%m-%d %H:%M:%S')}.{event_time.microsecond // 1000:03d}"
    event_sequence = int(event_time.timestamp() * 1000) % 10_000_000_000
    return (
        f"<181>{outer_timestamp} {appliance} {category} {message_id:010d} 1 0 "
        f"{inner_timestamp} +00:00 {event_sequence:010d} {event_code} NOTICE {description}, {details},"
    )
