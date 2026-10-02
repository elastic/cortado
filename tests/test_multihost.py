# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import importlib.util
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

from cortado.rtas import MultiHostRta, OSType, RtaParameter, get_registry
from cortado.rtas._cli import get_single_host_rtas_for_os, run_rta
from cortado.rtas._multihost import (
    EventWriter,
    LocalCoordinator,
    MultiHostError,
    RoleContext,
    StdinCoordinator,
    StdinLines,
    get_multihost_rta,
    parse_assignments,
    parse_peers,
    resolve_params,
    run_local,
)
from cortado.rtas._protocols.stun import transports
from cortado.rtas._protocols.stun.codec import (
    ATTR_DATA,
    BINDING_REQUEST,
    DATA_INDICATION,
    ProtocolError,
    decode_message,
    decode_payload_message,
    decode_xor_mapped_address,
    encode_message,
    encode_payload_message,
    encode_xor_mapped_address,
    sign_payload,
    verify_payload,
)
from cortado.rtas._protocols.stun.harness import Task, parse_command, perform_action
from cortado.rtas._protocols.stun.transports import MessageChannel

SECRET = b"unit-test-secret-value"
SOFTWARE = b"unit-test"
# python-mbedtls only supports Python 3.12; TLS uses the standard library on Python 3.13+
HAS_MBEDTLS = sys.version_info < (3, 13) and importlib.util.find_spec("mbedtls") is not None
HAS_TLS = transports.STDLIB_TLS_PSK or HAS_MBEDTLS
ALL_OS = [OSType.LINUX, OSType.MACOS, OSType.WINDOWS]


def _run_scenario(capsys: pytest.CaptureFixture[str], params: dict[str, str]) -> tuple[int, list[dict[str, str]]]:
    rta = get_multihost_rta("stun_turn_channel")
    code = run_local(rta, resolve_params(rta, params), timeout=60, port=0)
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    return code, events


# Registry and CLI


def test_stun_scenario_is_registered():
    rta = get_multihost_rta("stun_turn_channel")

    assert isinstance(rta, MultiHostRta)
    assert set(rta.roles) == {"server", "client"}
    assert rta.roles["server"].listens and not rta.roles["client"].listens
    assert json.loads(json.dumps(rta.as_dict()))["roles"][0]["name"] == "server"


def test_multihost_rtas_are_not_run_as_single_host_rtas():
    registry = get_registry()
    rtas = get_single_host_rtas_for_os(registry, OSType.LINUX)

    assert "stun_turn_channel" in registry
    assert all(not isinstance(r, MultiHostRta) for r in rtas)


def test_run_rta_points_to_multihost_cli(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "argv", ["cortado-run-rta", "stun_turn_channel"])

    with pytest.raises(ValueError, match="multi-host RTA"):
        run_rta()


def test_resolve_params_validates_names_and_choices():
    rta = get_multihost_rta("stun_turn_channel")

    assert resolve_params(rta, {"transport": "dtls"})["transport"] == "dtls"
    assert resolve_params(rta, {})["transport"] == "udp"
    with pytest.raises(MultiHostError, match="Unknown parameter"):
        _ = resolve_params(rta, {"bogus": "1"})
    with pytest.raises(MultiHostError, match="must be one of"):
        _ = resolve_params(rta, {"transport": "quic"})


def test_parse_assignments_and_peers():
    rta = get_multihost_rta("stun_turn_channel")
    client = rta.roles["client"]

    assert parse_assignments(["a=1", "b=x=y"]) == {"a": "1", "b": "x=y"}
    assert parse_peers(["10.0.0.5"], rta, client) == {"server": ("10.0.0.5", None)}
    assert parse_peers(["server=lab-a:3478"], rta, client) == {"server": ("lab-a", 3478)}
    with pytest.raises(MultiHostError):
        _ = parse_peers(["nobody=10.0.0.5"], rta, client)
    with pytest.raises(MultiHostError):
        _ = parse_assignments(["novalue"])


# STUN codec and harness


def test_stun_message_round_trip():
    encoded = encode_message(BINDING_REQUEST, ((ATTR_DATA, b"test"),), b"abcdefghijkl")
    decoded = decode_message(encoded)

    assert decoded.message_type == BINDING_REQUEST
    assert decoded.transaction_id == b"abcdefghijkl"
    assert decoded.get_attribute(ATTR_DATA) == b"test"
    assert encoded[4:8] == bytes.fromhex("2112a442")


def test_stun_rejects_invalid_messages():
    malformed = bytearray(encode_message(BINDING_REQUEST))
    malformed[4] ^= 1
    with pytest.raises(ProtocolError, match="magic cookie"):
        _ = decode_message(bytes(malformed))
    with pytest.raises(ProtocolError, match="transaction ID"):
        _ = encode_message(BINDING_REQUEST, transaction_id=b"")


def test_signed_payloads():
    payload = {"kind": "task", "action": "ping", "timestamp": time.time()}
    message = decode_message(encode_payload_message(DATA_INDICATION, payload, SECRET, SOFTWARE))
    assert decode_payload_message(message, DATA_INDICATION, SECRET)["action"] == "ping"

    tampered = sign_payload(payload, SECRET) | {"action": "echo"}
    with pytest.raises(ProtocolError, match="signature"):
        _ = verify_payload(json.dumps(tampered).encode(), SECRET)

    stale = sign_payload(payload | {"timestamp": time.time() - 120}, SECRET)
    with pytest.raises(ProtocolError, match="timestamp"):
        _ = verify_payload(json.dumps(stale).encode(), SECRET)
    assert verify_payload(json.dumps(stale).encode(), SECRET, max_age_secs=300)["kind"] == "task"

    with pytest.raises(ProtocolError):
        _ = encode_payload_message(DATA_INDICATION, {"timestamp": float("nan")}, SECRET, SOFTWARE)


def test_xor_mapped_address_round_trip():
    assert decode_xor_mapped_address(encode_xor_mapped_address("10.1.2.3", 3478)) == ("10.1.2.3", 3478)


def test_only_in_memory_actions_run():
    started = time.monotonic()

    assert perform_action("ping", {}, started, "svc") == {"reply": "pong"}
    assert perform_action("echo", {"text": "safe"}, started, "svc") == {"text": "safe"}
    assert perform_action("get_status", {}, started, "svc")["state"] == "ok"
    with pytest.raises(ProtocolError, match="allowlisted"):
        _ = perform_action("execute", {"value": "id"}, started, "svc")
    with pytest.raises(ProtocolError, match="256 bytes"):
        _ = perform_action("echo", {"text": "x" * 257}, started, "svc")


def test_only_fixed_commands_parse():
    assert parse_command("ping") == Task("ping")
    assert parse_command("status") == Task("get_status")
    assert parse_command("echo safe text") == Task("echo", {"text": "safe text"})
    assert parse_command("shell id") is None


class FakeConnection:
    def __init__(self, incoming: list[bytes]):
        self.incoming = list(incoming)
        self.sent = bytearray()

    def recv(self, bufsize: int, /) -> bytes:
        return self.incoming.pop(0)

    def send(self, data: bytes, /) -> int:
        self.sent.extend(data)
        return len(data)

    def sendall(self, data: bytes, /) -> None:
        self.sent.extend(data)

    def settimeout(self, value: float | None, /) -> None:
        pass

    def close(self) -> None:
        pass


def test_stream_channel_reassembles_fragmented_messages():
    first, second = encode_message(BINDING_REQUEST), encode_message(BINDING_REQUEST)
    channel = MessageChannel(FakeConnection([first[:7], first[7:] + second]), stream=True)

    assert channel.receive(1) == first
    assert channel.receive(1) == second


def test_stream_channel_framing_error_terminates_stream():
    malformed = bytearray(encode_message(BINDING_REQUEST))
    malformed[4] ^= 1
    channel = MessageChannel(FakeConnection([bytes(malformed)]), stream=True)

    with pytest.raises(ConnectionError, match="framing"):
        _ = channel.receive(1)


def test_missing_mbedtls_is_reported(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delitem(sys.modules, "cortado.rtas._protocols.stun.mbedtls_transport", raising=False)
    for module in ("mbedtls", "mbedtls.tls", "mbedtls.exceptions"):
        monkeypatch.setitem(sys.modules, module, None)  # type: ignore[arg-type]

    with pytest.raises(transports.MissingDependencyError, match="python-mbedtls"):
        _ = transports.open_listener("dtls", ("127.0.0.1", 0), SECRET)


# End-to-end runs over loopback


def test_local_run_over_udp(capsys: pytest.CaptureFixture[str]):
    code, events = _run_scenario(capsys, {"rounds": "1", "interval": "0"})

    assert code == 0
    results = [e for e in events if e["event"] == "task_result"]
    assert [e["action"] for e in results] == ["ping", "echo", "get_status"]
    assert all(e["ok"] for e in results)
    assert {e["role"] for e in events if e["event"] == "role_finished" and e["ok"]} == {"server", "client"}
    assert len({e["run_id"] for e in events}) == 1


@pytest.mark.parametrize(
    "transport",
    [
        pytest.param("tls", marks=pytest.mark.skipif(not HAS_TLS, reason="no TLS-PSK backend")),
        pytest.param("dtls", marks=pytest.mark.skipif(not HAS_MBEDTLS, reason="python-mbedtls is not installed")),
    ],
)
def test_local_run_over_encrypted_transports(capsys: pytest.CaptureFixture[str], transport: str):
    code, events = _run_scenario(capsys, {"transport": transport, "rounds": "2", "interval": "0.1", "keepalive": "0.2"})

    assert code == 0
    assert sum(e["event"] == "task_result" and e["ok"] for e in events) == 6
    assert any(e["event"] == "binding_refreshed" for e in events)


@pytest.mark.skipif(not HAS_TLS, reason="no TLS-PSK backend")
def test_tls_secret_mismatch_fails_fast():
    import threading

    listener = transports.open_listener("tls", ("127.0.0.1", 0), b"server-secret-0123456")
    server_errors: list[Exception] = []

    def accept() -> None:
        try:
            _ = listener.accept(10)
        except Exception as e:
            server_errors.append(e)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(ConnectionError, match="same secret"):
            _ = transports.connect("tls", listener.address, b"client-secret-0123456", timeout=10)
    finally:
        thread.join(10)
        listener.close()
    assert time.monotonic() - started < 5
    assert server_errors


def test_local_run_fails_on_invalid_task_plan(capsys: pytest.CaptureFixture[str]):
    code, _ = _run_scenario(capsys, {"tasks": "ping,unknown"})

    assert code == 1


# Coordination between roles


def _signal_rta() -> MultiHostRta:
    # Constructed directly (not registered) to keep the global registry unchanged
    rta = MultiHostRta(
        id="00000000-0000-0000-0000-000000000000",
        name="test_signals",
        platforms=ALL_OS,
        parameters=[RtaParameter("step", "one")],
    )

    @rta.role("first", listens=True)
    def first(ctx: RoleContext) -> None:  # type: ignore[reportUnusedFunction]
        ctx.ready()
        ctx.wait_for("second_started", timeout=10)
        ctx.signal("first_done")

    @rta.role("second")
    def second(ctx: RoleContext) -> None:  # type: ignore[reportUnusedFunction]
        ctx.signal("second_started")
        ctx.wait_for("first_done", timeout=10)

    return rta


def test_local_signals_order_roles(capsys: pytest.CaptureFixture[str]):
    rta = _signal_rta()

    assert run_local(rta, resolve_params(rta, {}), timeout=20) == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    names = [(e["role"], e["event"], e.get("name")) for e in events if e["event"] in ("signal", "role_finished")]
    assert names.index(("second", "signal", "second_started")) < names.index(("first", "signal", "first_done"))
    assert names[-1][1] == "role_finished"


def test_local_wait_times_out(capsys: pytest.CaptureFixture[str]):
    rta = MultiHostRta(id="0", name="test_wait_timeout", platforms=ALL_OS)

    @rta.role("only")
    def only(ctx: RoleContext) -> None:  # type: ignore[reportUnusedFunction]
        ctx.wait_for("never", timeout=0.2)

    assert run_local(rta, {}, timeout=5) == 1
    assert "Timed out waiting for signal" in capsys.readouterr().out


def test_driven_coordinator_reads_signals_from_stdin():
    read_fd, write_fd = os.pipe()
    _ = os.write(write_fd, b"early\ngo\n")
    rta = _signal_rta()
    ctx = RoleContext(
        rta=rta,
        role=rta.roles["second"],
        run_id="test",
        params={},
        secret=SECRET,
        deadline=time.monotonic() + 5,
        coordinator=StdinCoordinator("driven", StdinLines(read_fd)),
        events=EventWriter(io.StringIO()),
    )
    try:
        ctx.wait_for("go", timeout=1)
        # Signals received before being waited for are remembered
        ctx.wait_for("early", timeout=0.1)
        with pytest.raises(TimeoutError):
            ctx.wait_for("missing", timeout=0.2)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_manual_hint_contains_peer_command():
    rta = get_multihost_rta("stun_turn_channel")
    hints = io.StringIO()
    ctx = RoleContext(
        rta=rta,
        role=rta.roles["server"],
        run_id="abc",
        params=resolve_params(rta, {"transport": "dtls"}),
        secret=b"0123456789abcdef",
        deadline=time.monotonic() + 5,
        coordinator=StdinCoordinator("manual", hint_stream=hints),
        events=EventWriter(io.StringIO()),
        bind_host="10.1.1.5",
        param_overrides={"transport": "dtls"},
    )
    ctx.ready(port=5349)

    assert (
        "env CORTADO_MULTIHOST_SECRET=0123456789abcdef cortado-run-multihost-rta run stun_turn_channel "
        "--role client --peer server=10.1.1.5:5349 --run-id abc -p transport=dtls"
    ) in hints.getvalue()


def test_local_coordinator_records_ready_port():
    coordinator = LocalCoordinator()
    rta = _signal_rta()
    ctx = RoleContext(
        rta=rta,
        role=rta.roles["first"],
        run_id="test",
        params={},
        secret=SECRET,
        deadline=time.monotonic() + 5,
        coordinator=coordinator,
        events=EventWriter(io.StringIO()),
    )
    ctx.ready(port=1234)

    assert coordinator.ready_event("first").is_set()
    assert coordinator.ready_ports["first"] == 1234


# Optional SSH driver, exercised with a fake `ssh` that runs the remote command locally

REMOTE_CLI = Path(sys.executable).parent / "cortado-run-multihost-rta"


@pytest.mark.skipif(not REMOTE_CLI.exists(), reason="cortado-run-multihost-rta entry point is not installed")
def test_driver_runs_roles_over_ssh(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    from cortado import multihost_driver

    fake_ssh = tmp_path / "fake_ssh.py"
    _ = fake_ssh.write_text("import os, sys\nos.execvp('bash', ['bash', '-c', sys.argv[2]])\n")
    rta = get_multihost_rta("stun_turn_channel")
    targets = multihost_driver.parse_host_targets(
        rta, ["server=lab@server-host", "client=lab@client-host"], ["server=127.0.0.1"]
    )
    assert targets["client"].address == "client-host"

    output = io.StringIO()
    code = multihost_driver.drive(
        rta,
        targets,
        {"rounds": "1", "interval": "0"},
        timeout=60,
        port=0,
        ssh_command=f"{sys.executable} {fake_ssh}",
        remote_command=str(REMOTE_CLI),
        output=output,
    )

    assert code == 0
    events = [json.loads(line) for line in output.getvalue().splitlines()]
    assert sum(e["event"] == "task_result" and e["ok"] for e in events) == 3
    assert len({e["run_id"] for e in events}) == 1
    _ = capsys.readouterr()


def test_driver_requires_a_host_per_role():
    from cortado import multihost_driver

    rta = get_multihost_rta("stun_turn_channel")
    with pytest.raises(MultiHostError, match="client"):
        _ = multihost_driver.parse_host_targets(rta, ["server=lab-a"], [])
