# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import socket
from datetime import UTC, datetime
from unittest.mock import MagicMock, call, patch

import pytest

from cortado.rtas._cisco_syslog import (
    DEFAULT_SYSLOG_HOST,
    DEFAULT_SYSLOG_PORT,
    SyslogConfig,
    SyslogConfigurationError,
    build_asa_message,
    build_ise_message,
    config_from_environment,
    send_syslog,
)

SYSLOG_ENVIRONMENT_VARIABLES = (
    "CORTADO_SYSLOG_HOST",
    "CORTADO_SYSLOG_PORT",
    "CORTADO_SYSLOG_PROTOCOL",
    "CORTADO_SYSLOG_ALLOW_REMOTE",
    "CORTADO_SYSLOG_DRY_RUN",
)


def test_config_from_environment_defaults(monkeypatch):
    for variable in SYSLOG_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)

    assert config_from_environment() == SyslogConfig(
        host=DEFAULT_SYSLOG_HOST,
        port=DEFAULT_SYSLOG_PORT,
        protocol="udp",
        allow_remote=False,
        dry_run=False,
    )


@pytest.mark.parametrize(
    ("variable", "value", "error"),
    [
        ("CORTADO_SYSLOG_HOST", "bad host", "HOST"),
        ("CORTADO_SYSLOG_PORT", "0", "PORT"),
        ("CORTADO_SYSLOG_PORT", "not-a-port", "PORT"),
        ("CORTADO_SYSLOG_PROTOCOL", "tls", "PROTOCOL"),
        ("CORTADO_SYSLOG_ALLOW_REMOTE", "true", "ALLOW_REMOTE"),
        ("CORTADO_SYSLOG_DRY_RUN", "yes", "DRY_RUN"),
    ],
)
def test_config_from_environment_rejects_invalid_values(monkeypatch, variable, value, error):
    for environment_variable in SYSLOG_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(environment_variable, raising=False)
    monkeypatch.setenv(variable, value)

    with pytest.raises(SyslogConfigurationError, match=error):
        config_from_environment()


def test_send_syslog_refuses_remote_destination():
    config = SyslogConfig(
        host="192.0.2.10",
        port=9514,
        protocol="udp",
        allow_remote=False,
        dry_run=True,
    )

    with pytest.raises(SyslogConfigurationError, match="CORTADO_SYSLOG_ALLOW_REMOTE=1"):
        send_syslog(["synthetic event"], config)


def test_send_syslog_uses_one_udp_datagram_per_event():
    config = SyslogConfig(
        host="127.0.0.1",
        port=9514,
        protocol="udp",
        allow_remote=False,
        dry_run=False,
    )
    socket_context = MagicMock()
    syslog_socket = socket_context.__enter__.return_value
    address_info = [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", ("127.0.0.1", 9514))]
    syslog_socket.sendto.side_effect = lambda payload, _destination: len(payload)

    with (
        patch("cortado.rtas._cisco_syslog.socket.getaddrinfo", return_value=address_info),
        patch("cortado.rtas._cisco_syslog.socket.socket", return_value=socket_context),
    ):
        send_syslog(["first event", "second event"], config)

    assert syslog_socket.sendto.call_args_list == [
        call(b"first event", ("127.0.0.1", 9514)),
        call(b"second event", ("127.0.0.1", 9514)),
    ]


def test_send_syslog_uses_newline_delimited_tcp():
    config = SyslogConfig(
        host="127.0.0.1",
        port=9514,
        protocol="tcp",
        allow_remote=False,
        dry_run=False,
    )
    socket_context = MagicMock()
    syslog_socket = socket_context.__enter__.return_value
    address_info = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 9514))]

    with (
        patch("cortado.rtas._cisco_syslog.socket.getaddrinfo", return_value=address_info),
        patch("cortado.rtas._cisco_syslog.socket.socket", return_value=socket_context),
    ):
        send_syslog(["first event", "second event"], config)

    syslog_socket.connect.assert_called_once_with(("127.0.0.1", 9514))
    assert syslog_socket.sendall.call_args_list == [
        call(b"first event\n"),
        call(b"second event\n"),
    ]


def test_send_syslog_dry_run_logs_payload(caplog):
    config = SyslogConfig(
        host="127.0.0.1",
        port=9514,
        protocol="udp",
        allow_remote=False,
        dry_run=True,
    )

    with caplog.at_level(logging.INFO):
        send_syslog(["synthetic event"], config)

    assert "Dry-run Cisco syslog payload: synthetic event" in caplog.text


def test_build_asa_message_uses_pinned_fixture_shape():
    timestamp = datetime(2026, 11, 12, 20, 1, 2, tzinfo=UTC)

    message = build_asa_message(
        111010,
        "User 'rta-admin', running 'CLI' from IP 192.0.2.10, executed 'no logging enable'",
        appliance="asa-rta",
        timestamp=timestamp,
    )

    assert message == (
        "<181>2026-11-12T20:01:02Z asa-rta: %ASA-5-111010: "
        "User 'rta-admin', running 'CLI' from IP 192.0.2.10, executed 'no logging enable'"
    )


def test_build_ise_message_uses_pinned_fixture_shape():
    timestamp = datetime(2026, 11, 12, 20, 1, 2, 345000, tzinfo=UTC)

    message = build_ise_message(
        category="CISE_TACACS_Accounting",
        message_id=1,
        event_code=3300,
        description="Tacacs-Accounting: TACACS+ Accounting with Command",
        details="Device IP Address=192.0.2.20, Privilege-Level=15",
        timestamp=timestamp,
    )

    assert message.startswith(
        "<181>Nov 12 20:01:02 ise-rta CISE_TACACS_Accounting 0000000001 1 0 "
        "2026-11-12 20:01:02.345 +00:00 "
    )
    assert message.endswith(
        " 3300 NOTICE Tacacs-Accounting: TACACS+ Accounting with Command, "
        "Device IP Address=192.0.2.20, Privilege-Level=15,"
    )
