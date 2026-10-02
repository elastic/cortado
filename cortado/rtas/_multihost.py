# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Runtime for multi-host RTAs.

Each role of a `MultiHostRta` runs as its own process, normally on its own host. Roles communicate their state
through JSON events printed to stdout (`role_ready`, `signal`, `role_finished`, ...) and receive coordination
input on stdin. This is the same channel in every mode, so no extra network traffic is generated in the lab:

- manual (default): the operator reads the events and presses Enter where a role waits for its peer
- driven: an orchestrator (e.g. `cortado run-multihost` over SSH) reads events and writes signal names to stdin
- local: all roles run as threads on one host over loopback, for smoke tests
"""

import json
import logging
import os
import platform
import secrets
import select
import shlex
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, TextIO

from cortado.rtas import MultiHostRta, Role, get_registry, load_multihost_module, load_multihost_modules
from cortado.rtas._common import get_current_os, get_host_ip, get_hostname

log = logging.getLogger(__name__)

SECRET_ENV_VAR = "CORTADO_MULTIHOST_SECRET"
DEFAULT_TIMEOUT_SECS = 300.0
LOCAL_HOST = "127.0.0.1"
MIN_SECRET_BYTES = 16
MAX_SECRET_BYTES = 64

CoordinationMode = Literal["manual", "driven", "no-wait"]

# Events emitted by the runtime itself; everything else comes from the role code
EVENT_ROLE_STARTED = "role_started"
EVENT_ROLE_READY = "role_ready"
EVENT_ROLE_FINISHED = "role_finished"
EVENT_SIGNAL = "signal"
EVENT_WAITING = "waiting_for_signal"


class MultiHostError(Exception):
    """Raised for invalid multi-host RTA invocations"""


# Parsing helpers


def get_multihost_rta(name: str) -> MultiHostRta:
    """Load and return a multi-host RTA by name"""
    try:
        # By convention the module is named after the RTA
        load_multihost_module(name)
    except ValueError:
        _ = load_multihost_modules()

    rta = get_registry().get(name)
    if not isinstance(rta, MultiHostRta):
        raise MultiHostError(f"Can't find multi-host RTA `{name}`")
    return rta


def get_multihost_rtas() -> list[MultiHostRta]:
    _ = load_multihost_modules()
    return sorted((r for r in get_registry().values() if isinstance(r, MultiHostRta)), key=lambda r: r.name)


def parse_assignments(values: list[str]) -> dict[str, str]:
    """Parse `NAME=VALUE` strings"""
    result: dict[str, str] = {}
    for value in values:
        name, sep, assigned = value.partition("=")
        if not sep or not name:
            raise MultiHostError(f"Expected NAME=VALUE, got `{value}`")
        result[name.strip()] = assigned
    return result


def resolve_params(rta: MultiHostRta, overrides: dict[str, str]) -> dict[str, str]:
    """Merge parameter overrides with defaults, validating names and choices"""
    known = {p.name: p for p in rta.parameters}
    unknown = sorted(set(overrides) - set(known))
    if unknown:
        raise MultiHostError(f"Unknown parameter(s) for `{rta.name}`: {', '.join(unknown)}. Known: {', '.join(known)}")

    params: dict[str, str] = {}
    for name, spec in known.items():
        value = overrides.get(name, spec.default)
        if spec.choices and value not in spec.choices:
            raise MultiHostError(f"Parameter `{name}` must be one of: {', '.join(spec.choices)} (got `{value}`)")
        params[name] = value
    return params


def parse_address(value: str) -> tuple[str, int | None]:
    """Parse `HOST` or `HOST:PORT` (IPv4 addresses and hostnames)"""
    host, sep, port = value.rpartition(":")
    if not sep:
        return value, None
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise MultiHostError(f"Invalid address `{value}`, expected HOST or HOST:PORT")
    return host, int(port)


def parse_peers(values: list[str], rta: MultiHostRta, role: Role) -> dict[str, tuple[str, int | None]]:
    """Parse `--peer` values: `ROLE=HOST[:PORT]`, or `HOST[:PORT]` when there is one listening peer role"""
    listening_peers = [r.name for r in rta.roles.values() if r.listens and r.name != role.name]
    peers: dict[str, tuple[str, int | None]] = {}
    for value in values:
        peer_role, sep, address = value.partition("=")
        if not sep:
            if len(listening_peers) != 1:
                raise MultiHostError(f"Use ROLE=HOST[:PORT] for `--peer`, peer roles: {', '.join(listening_peers)}")
            peer_role, address = listening_peers[0], value
        if peer_role not in rta.roles:
            raise MultiHostError(f"Unknown peer role `{peer_role}`, roles: {', '.join(rta.roles)}")
        peers[peer_role] = parse_address(address)
    return peers


def generate_secret() -> str:
    return secrets.token_hex(MIN_SECRET_BYTES)


def validate_secret(secret: str) -> bytes:
    encoded = secret.encode("utf-8")
    if not MIN_SECRET_BYTES <= len(encoded) <= MAX_SECRET_BYTES:
        raise MultiHostError(f"The shared secret must be {MIN_SECRET_BYTES}-{MAX_SECRET_BYTES} UTF-8 bytes")
    return encoded


def generate_run_id() -> str:
    return uuid.uuid4().hex[:12]


# Events


class EventWriter:
    """Thread-safe writer of JSON event lines (ground truth for correlation with detections)"""

    def __init__(self, stream: TextIO | None = None):
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True, default=str)
        with self._lock:
            stream: TextIO = self._stream or sys.stdout
            _ = stream.write(line + "\n")
            stream.flush()


# Coordination


class Coordinator(Protocol):
    def on_ready(self, ctx: "RoleContext", port: int | None) -> None: ...

    def on_signal(self, ctx: "RoleContext", name: str) -> None: ...

    def wait_for(self, ctx: "RoleContext", name: str, timeout: float) -> bool: ...


class StdinLines:
    """Line reader over the stdin file descriptor with timeouts (Linux/macOS)"""

    def __init__(self, fd: int | None = None):
        self._fd = fd if fd is not None else sys.stdin.fileno()
        self._buffer = bytearray()
        self._eof = False

    def readline(self, timeout: float) -> str | None:
        """Return the next line without the line break, or `None` on timeout or EOF"""
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if self._eof or remaining <= 0:
                return None
            readable, _, _ = select.select([self._fd], [], [], remaining)
            if not readable:
                return None
            chunk = os.read(self._fd, 4096)
            if not chunk:
                self._eof = True
                continue
            self._buffer.extend(chunk)
        line, _, rest = bytes(self._buffer).partition(b"\n")
        self._buffer = bytearray(rest)
        return line.decode("utf-8", errors="replace").strip()


class StdinCoordinator:
    """Coordinates with peers through the operator (manual) or an orchestrator (driven) via stdin"""

    def __init__(self, mode: CoordinationMode, lines: StdinLines | None = None, hint_stream: TextIO | None = None):
        self.mode: CoordinationMode = mode
        self._lines = lines
        self._received: set[str] = set()
        self._hint_stream = hint_stream

    def _hint(self, text: str) -> None:
        if self.mode != "driven":
            print(text, file=self._hint_stream or sys.stderr, flush=True)

    def on_ready(self, ctx: "RoleContext", port: int | None) -> None:
        self._hint(format_ready_hint(ctx, port))

    def on_signal(self, ctx: "RoleContext", name: str) -> None:
        self._hint(f"Role `{ctx.role.name}` sent signal `{name}`. Continue any peer role waiting for it.")

    def wait_for(self, ctx: "RoleContext", name: str, timeout: float) -> bool:
        if self.mode == "no-wait":
            log.warning(f"Not waiting for signal `{name}` (--no-wait)")
            return True
        if self._lines is None:
            self._lines = StdinLines()

        if self.mode == "manual":
            self._hint(f"Role `{ctx.role.name}` is waiting for signal `{name}` from a peer. Press Enter to continue.")
            return self._lines.readline(timeout) is not None

        # Driven: the orchestrator broadcasts every signal name; remember ones received before they were awaited
        deadline = time.monotonic() + timeout
        while name not in self._received:
            line = self._lines.readline(deadline - time.monotonic())
            if line is None:
                return False
            self._received.add(line)
        return True


class LocalCoordinator:
    """Coordinates roles running as threads in the same process"""

    def __init__(self):
        self._lock = threading.Lock()
        self._signals: dict[str, threading.Event] = {}
        self.ready_events: dict[str, threading.Event] = {}
        self.ready_ports: dict[str, int | None] = {}

    def _event(self, events: dict[str, threading.Event], name: str) -> threading.Event:
        with self._lock:
            return events.setdefault(name, threading.Event())

    def ready_event(self, role: str) -> threading.Event:
        return self._event(self.ready_events, role)

    def on_ready(self, ctx: "RoleContext", port: int | None) -> None:
        self.ready_ports[ctx.role.name] = port
        self.ready_event(ctx.role.name).set()

    def on_signal(self, ctx: "RoleContext", name: str) -> None:
        self._event(self._signals, name).set()

    def wait_for(self, ctx: "RoleContext", name: str, timeout: float) -> bool:
        return self._event(self._signals, name).wait(timeout)


# Role context


@dataclass
class RoleContext:
    """Everything a role function needs to run and to coordinate with its peers"""

    rta: MultiHostRta
    role: Role
    run_id: str
    params: dict[str, str]
    secret: bytes
    deadline: float
    coordinator: Coordinator
    events: EventWriter
    bind_host: str = LOCAL_HOST
    port: int | None = None
    peers: dict[str, tuple[str, int | None]] = field(default_factory=lambda: {})
    # Parameters explicitly set by the operator; used to build commands for peer hosts
    param_overrides: dict[str, str] = field(default_factory=lambda: {})
    host: str = field(default_factory=get_hostname)

    def event(self, event: str, /, **fields: Any) -> None:
        """Emit one structured ground-truth event"""
        self.events.write(
            {
                "timestamp": round(time.time(), 3),
                "run_id": self.run_id,
                "rta": self.rta.name,
                "role": self.role.name,
                "host": self.host,
                "event": event,
                **fields,
            }
        )

    def remaining(self) -> float:
        return max(self.deadline - time.monotonic(), 0.0)

    def param(self, name: str) -> str:
        return self.params[name]

    def param_int(self, name: str) -> int:
        try:
            return int(self.params[name])
        except ValueError:
            raise MultiHostError(f"Parameter `{name}` must be an integer (got `{self.params[name]}`)")

    def param_float(self, name: str) -> float:
        try:
            return float(self.params[name])
        except ValueError:
            raise MultiHostError(f"Parameter `{name}` must be a number (got `{self.params[name]}`)")

    def param_bool(self, name: str) -> bool:
        return self.params[name].lower() in ("1", "true", "yes", "on")

    def bind_address(self, default_port: int) -> tuple[str, int]:
        """Local address a listening role binds to"""
        return self.bind_host, self.port if self.port is not None else default_port

    def peer_address(self, default_port: int, role: str | None = None) -> tuple[str, int]:
        """Address of a peer role; defaults to the only peer given"""
        if role is None:
            if len(self.peers) != 1:
                raise MultiHostError(f"Role `{self.role.name}` needs exactly one `--peer`, got {len(self.peers)}")
            role = next(iter(self.peers))
        if role not in self.peers:
            raise MultiHostError(f"No `--peer` address given for role `{role}`")
        host, port = self.peers[role]
        if port is None:
            port = self.port if self.port is not None else default_port
        return host, port

    def ready(self, port: int | None = None, **fields: Any) -> None:
        """Announce that this (listening) role accepts peers, optionally with the port it actually bound"""
        self.event(EVENT_ROLE_READY, port=port, **fields)
        self.coordinator.on_ready(self, port)

    def signal(self, name: str) -> None:
        """Tell peer roles that step `name` is done"""
        self.event(EVENT_SIGNAL, name=name)
        self.coordinator.on_signal(self, name)

    def wait_for(self, name: str, timeout: float | None = None) -> None:
        """Block until a peer role sends signal `name`; raises `TimeoutError` at the timeout or role deadline"""
        self.event(EVENT_WAITING, name=name)
        timeout = self.remaining() if timeout is None else min(timeout, self.remaining())
        if not self.coordinator.wait_for(self, name, timeout):
            raise TimeoutError(f"Timed out waiting for signal `{name}`")


def format_ready_hint(ctx: RoleContext, port: int | None) -> str:
    """Build copy-paste commands for the peer hosts of a ready listening role"""
    host = ctx.bind_host
    lines: list[str] = []
    if host in ("0.0.0.0", ""):
        host = get_host_ip()
    elif host.startswith("127."):
        lines.append(
            f"NOTE: `{ctx.role.name}` is bound to loopback; use `--bind 0.0.0.0` (or a lab interface address) "
            "to accept a peer on another host."
        )

    address = f"{host}:{port}" if port is not None else host
    lines.insert(0, f"Role `{ctx.role.name}` of `{ctx.rta.name}` is ready (run_id={ctx.run_id}, address={address}).")
    other_roles = [r for r in ctx.rta.roles.values() if r.name != ctx.role.name]
    if other_roles:
        lines.append("Run on the peer host(s):")
    for role in other_roles:
        args = ["cortado-run-multihost-rta", "run", ctx.rta.name, "--role", role.name]
        args += ["--peer", f"{ctx.role.name}={address}", "--run-id", ctx.run_id]
        for name, value in sorted(ctx.param_overrides.items()):
            args += ["-p", f"{name}={value}"]
        secret = shlex.quote(ctx.secret.decode("utf-8"))
        lines.append(f"  env {SECRET_ENV_VAR}={secret} {shlex.join(args)}")
    return "\n".join(lines)


# Execution


def run_role(ctx: RoleContext) -> int:
    """Run one role and return its exit code"""
    ctx.event(
        EVENT_ROLE_STARTED,
        params=ctx.params,
        platform=platform.platform(),
        pid=os.getpid(),
    )
    current_os = get_current_os()
    if current_os not in ctx.role.platforms:
        reason = f"Role `{ctx.role.name}` doesn't support `{current_os}`"
        log.error(reason)
        ctx.event(EVENT_ROLE_FINISHED, ok=False, error=reason)
        return 1

    try:
        ctx.role.func(ctx)
    except KeyboardInterrupt:
        ctx.event(EVENT_ROLE_FINISHED, ok=False, error="interrupted")
        return 130
    except ImportError as e:
        # Missing optional dependency: the message says what to install, a traceback adds nothing
        log.error(f"Role `{ctx.role.name}` of `{ctx.rta.name}` can't run: {e}")
        ctx.event(EVENT_ROLE_FINISHED, ok=False, error=f"{type(e).__name__}: {e}")
        return 1
    except Exception as e:
        log.error(f"Role `{ctx.role.name}` of `{ctx.rta.name}` failed", exc_info=True)
        ctx.event(EVENT_ROLE_FINISHED, ok=False, error=f"{type(e).__name__}: {e}")
        return 1

    ctx.event(EVENT_ROLE_FINISHED, ok=True)
    return 0


def run_local(
    rta: MultiHostRta,
    params: dict[str, str],
    timeout: float = DEFAULT_TIMEOUT_SECS,
    port: int | None = None,
    run_id: str | None = None,
    events: EventWriter | None = None,
) -> int:
    """Run all roles on this host over loopback: listening roles first, then the rest"""
    if not rta.roles:
        raise MultiHostError(f"RTA `{rta.name}` has no roles")

    run_id = run_id or generate_run_id()
    secret = validate_secret(generate_secret())
    deadline = time.monotonic() + timeout
    coordinator = LocalCoordinator()
    events = events or EventWriter()
    exit_codes: dict[str, int] = {}

    def make_context(role: Role, peers: dict[str, tuple[str, int | None]]) -> RoleContext:
        return RoleContext(
            rta=rta,
            role=role,
            run_id=run_id,
            params=params,
            secret=secret,
            deadline=deadline,
            coordinator=coordinator,
            events=events,
            bind_host=LOCAL_HOST,
            port=port,
            peers=peers,
        )

    def start(ctx: RoleContext) -> threading.Thread:
        def target() -> None:
            exit_codes[ctx.role.name] = run_role(ctx)

        thread = threading.Thread(target=target, name=f"role-{ctx.role.name}", daemon=True)
        thread.start()
        return thread

    listening = [r for r in rta.roles.values() if r.listens]
    connecting = [r for r in rta.roles.values() if not r.listens]
    threads: list[threading.Thread] = []

    for role in listening:
        thread = start(make_context(role, {}))
        threads.append(thread)
        ready = coordinator.ready_event(role.name)
        while not ready.wait(0.1):
            if not thread.is_alive() or time.monotonic() > deadline:
                log.error(f"Listening role `{role.name}` exited or timed out before it was ready")
                for t in threads:
                    t.join(max(deadline - time.monotonic(), 0))
                return 1

    peers = {r.name: (LOCAL_HOST, coordinator.ready_ports.get(r.name)) for r in listening}
    for role in connecting:
        threads.append(start(make_context(role, peers)))

    for thread in threads:
        # Roles enforce the deadline themselves; the grace period covers cleanup
        thread.join(max(deadline - time.monotonic(), 0) + 5)

    for role in rta.roles.values():
        if role.name not in exit_codes:
            log.error(f"Role `{role.name}` did not finish in time")
            exit_codes[role.name] = 1

    failed = sorted(name for name, code in exit_codes.items() if code != 0)
    if failed:
        log.error(f"Local run of `{rta.name}` failed for role(s): {', '.join(failed)}")
        return 1
    log.info(f"Local run of `{rta.name}` succeeded (run_id={run_id})")
    return 0
