# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Optional orchestrator that runs the roles of a multi-host RTA over SSH.

This is opt-in: manual mode (`cortado-run-multihost-rta run NAME --role ROLE` on each host) needs no extra
channel, while SSH sessions add their own traffic and logins to the lab data. When used, the driver:

1. starts listening roles with `--driven --secret-stdin` and sends them a per-run secret on stdin
2. waits for their `role_ready` events (and actual ports), then starts the connecting roles
3. relays `signal` events from any role to the stdin of all other roles
4. merges every role's JSON events into one stream keyed by `run_id`

It uses the system `ssh` client, so it has no Python dependencies. Each role still enforces its own timeout if
the SSH session is lost.
"""

import json
import queue
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import IO, Any, TextIO

import structlog

from cortado.rtas import MultiHostRta
from cortado.rtas._multihost import (
    EVENT_ROLE_READY,
    EVENT_SIGNAL,
    MultiHostError,
    generate_run_id,
    generate_secret,
    parse_assignments,
    resolve_params,
)

log = structlog.get_logger(__name__)

DEFAULT_SSH_COMMAND = "ssh -T -o BatchMode=yes"
DEFAULT_REMOTE_COMMAND = "cortado-run-multihost-rta"
# Time for roles to exit after their own deadline before they're killed
EXIT_GRACE_SECS = 15.0


@dataclass(frozen=True)
class HostTarget:
    role: str
    # `[user@]host` passed to ssh
    ssh_target: str
    # Address peers connect to; may differ from the SSH (management) address
    address: str


def parse_host_targets(rta: MultiHostRta, hosts: list[str], addresses: list[str]) -> dict[str, HostTarget]:
    """Parse `ROLE=[USER@]HOST` SSH targets and optional `ROLE=IP` lab addresses"""
    ssh_targets = parse_assignments(hosts)
    lab_addresses = parse_assignments(addresses)
    for role in set(ssh_targets) | set(lab_addresses):
        if role not in rta.roles:
            raise MultiHostError(f"Unknown role `{role}`, roles of `{rta.name}`: {', '.join(rta.roles)}")
    missing = [r for r in rta.roles if r not in ssh_targets]
    if missing:
        raise MultiHostError(f"No `--host ROLE=[USER@]HOST` given for role(s): {', '.join(missing)}")
    return {
        role: HostTarget(role=role, ssh_target=target, address=lab_addresses.get(role, target.rpartition("@")[2]))
        for role, target in ssh_targets.items()
    }


class _RoleProcess:
    def __init__(self, target: HostTarget, argv: list[str], events: "queue.Queue[tuple[str, dict[str, Any] | None]]"):
        self.target = target
        self.role = target.role
        log.info("Starting role", role=self.role, host=target.ssh_target, argv=argv)
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        self._events = events
        assert self.proc.stdout is not None and self.proc.stderr is not None
        threading.Thread(target=self._read_events, args=(self.proc.stdout,), daemon=True).start()
        threading.Thread(target=self._forward_logs, args=(self.proc.stderr,), daemon=True).start()

    def _read_events(self, stream: IO[str]) -> None:
        for line in stream:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = None
            if isinstance(record, dict) and "run_id" in record:
                self._events.put((self.role, record))  # type: ignore[arg-type]
            elif line.strip():
                print(f"[{self.role}] {line.rstrip()}", file=sys.stderr, flush=True)
        self._events.put((self.role, None))

    def _forward_logs(self, stream: IO[str]) -> None:
        for line in stream:
            print(f"[{self.role}] {line.rstrip()}", file=sys.stderr, flush=True)

    def send_line(self, text: str) -> None:
        if self.proc.stdin is None or self.proc.poll() is not None:
            return
        try:
            _ = self.proc.stdin.write(text + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            log.debug("Can't write to role stdin", role=self.role)

    def stop(self) -> None:
        if self.proc.poll() is None:
            log.warning("Terminating role", role=self.role)
            self.proc.terminate()
            try:
                _ = self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _role_command(
    rta: MultiHostRta,
    target: HostTarget,
    remote_command: list[str],
    run_id: str,
    overrides: dict[str, str],
    timeout: float,
    port: int | None,
    peers: dict[str, str],
) -> list[str]:
    role = rta.roles[target.role]
    args = [*remote_command, "run", rta.name, "--role", role.name, "--driven", "--secret-stdin"]
    args += ["--run-id", run_id, "--timeout", str(timeout)]
    if role.listens:
        args += ["--bind", "0.0.0.0"]
        if port is not None:
            args += ["--port", str(port)]
    for peer_role, address in peers.items():
        args += ["--peer", f"{peer_role}={address}"]
    for name, value in sorted(overrides.items()):
        args += ["-p", f"{name}={value}"]
    return args


def drive(
    rta: MultiHostRta,
    targets: dict[str, HostTarget],
    overrides: dict[str, str],
    timeout: float,
    port: int | None = None,
    ssh_command: str = DEFAULT_SSH_COMMAND,
    remote_command: str = DEFAULT_REMOTE_COMMAND,
    output: TextIO | None = None,
    run_id: str | None = None,
) -> int:
    """Run all roles of `rta` on their SSH targets and return 0 if every role succeeded"""
    _ = resolve_params(rta, overrides)  # fail early on invalid parameters
    run_id = run_id or generate_run_id()
    secret = generate_secret()
    ssh_argv = shlex.split(ssh_command)
    remote_argv = shlex.split(remote_command)
    events: queue.Queue[tuple[str, dict[str, Any] | None]] = queue.Queue()
    processes: dict[str, _RoleProcess] = {}
    finished: set[str] = set()
    results: dict[str, bool] = {}
    deadline = time.monotonic() + timeout + EXIT_GRACE_SECS
    _log = log.bind(rta=rta.name, run_id=run_id)

    def start(target: HostTarget, peers: dict[str, str]) -> None:
        command = _role_command(rta, target, remote_argv, run_id, overrides, timeout, port, peers)
        process = _RoleProcess(target, [*ssh_argv, target.ssh_target, shlex.join(command)], events)
        process.send_line(secret)
        processes[target.role] = process

    def next_event() -> tuple[str, dict[str, Any] | None] | None:
        """Handle and return the next role event, or `None` at the deadline"""
        try:
            role, record = events.get(timeout=max(deadline - time.monotonic(), 0.01))
        except queue.Empty:
            return None
        if record is None:
            finished.add(role)
            return role, None
        line = json.dumps(record, sort_keys=True)
        print(line, flush=True)
        if output:
            _ = output.write(line + "\n")
            output.flush()
        if record.get("event") == "role_finished":
            results[role] = bool(record.get("ok"))
        if record.get("event") == EVENT_SIGNAL:
            # Broadcast; roles remember signals received before they wait for them
            for other_role, process in processes.items():
                if other_role != role:
                    process.send_line(str(record.get("name")))
        return role, record

    listening = [targets[r.name] for r in rta.roles.values() if r.listens]
    connecting = [targets[r.name] for r in rta.roles.values() if not r.listens]
    ready_ports: dict[str, int | None] = {}

    try:
        for target in listening:
            start(target, {})
        while len(ready_ports) < len(listening):
            item = next_event()
            if item is None:
                _log.error("Timed out waiting for listening roles to become ready")
                return 1
            role, record = item
            if record is None:
                _log.error("Role exited before it was ready", role=role)
                return 1
            if record.get("event") == EVENT_ROLE_READY:
                ready_ports[role] = record.get("port")

        peers = {
            t.role: f"{t.address}:{ready_ports[t.role]}" if ready_ports[t.role] else t.address for t in listening
        }
        for target in connecting:
            start(target, peers)

        while len(finished) < len(processes):
            if next_event() is None:
                _log.error("Timed out waiting for roles to finish")
                return 1
    finally:
        for process in processes.values():
            process.stop()

    failed = False
    for role, process in processes.items():
        code = process.proc.wait()
        if code != 0 or not results.get(role):
            _log.error("Role failed", role=role, exit_code=code)
            failed = True
    if failed:
        return 1
    _log.info("All roles succeeded")
    return 0
