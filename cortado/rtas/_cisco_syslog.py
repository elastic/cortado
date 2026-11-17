# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Build synthetic Cisco syslog events.

The destination Elastic Agent input determines ``data_stream.dataset``. These
messages must be sent to a Cisco ASA, Cisco Secure Firewall Threat Defense, or
Cisco ISE integration listener as appropriate; the sender cannot select the
dataset.

Message shapes follow the Cisco ASA, FTD, and ISE fixtures and ingest pipelines
at ``elastic/integrations@4c0916e8faf8172686249fa33308f1f9e8f077aa``.
"""

from datetime import UTC, datetime

from ._syslog import (
    DEFAULT_SYSLOG_HOST,
    DEFAULT_SYSLOG_PORT,
    SyslogConfig,
    SyslogConfigurationError,
    SyslogTransmissionError,
    config_from_environment,
    send_syslog,
)

__all__ = [
    "DEFAULT_SYSLOG_HOST",
    "DEFAULT_SYSLOG_PORT",
    "SyslogConfig",
    "SyslogConfigurationError",
    "SyslogTransmissionError",
    "build_asa_message",
    "build_ise_message",
    "config_from_environment",
    "send_syslog",
]


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
