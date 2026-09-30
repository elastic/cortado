# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: STUN/TURN-like Task Channel Between Two Hosts
# RTA: multihost/stun_turn_channel.py
# Description: A server role and a client role exchange a constrained task channel framed as STUN/TURN:
#              the client registers with authenticated STUN Binding requests (refreshed as keepalives), and
#              the server sends allowlisted tasks in TURN-like Data Indications (type 0x0017) that the client
#              answers. This produces real, bidirectional flows that both hosts' endpoint agents and any
#              network sensor in between (Zeek, pfSense, ...) observe.
#
#              Transports (`-p transport=...`):
#                - udp:  cleartext STUN framing on UDP/3478; payloads are visible to protocol parsers
#                - tls:  the same messages inside PSK-authenticated TLS 1.2+ on TCP/5349
#                - dtls: the same messages inside PSK-authenticated DTLS 1.2 on UDP/5349
#              tls uses the standard library on Python 3.13+ and python-mbedtls on Python 3.12. dtls needs
#              python-mbedtls (`cortado[protocols]` extra), which only supports Python 3.12. Both backends
#              negotiate TLS 1.2 ECDHE-PSK-CHACHA20-POLY1305, so hosts on different Python versions interoperate.
#
#              Safety: the client can only answer `ping`, bounded `echo`, and an in-memory `get_status`. It
#              has no command execution, file access, host inventory, or code loading. All payloads are
#              HMAC-SHA256 signed and freshness-checked (host clocks must be within `max_skew` seconds).
#              Data Indications omit XOR-PEER-ADDRESS; this is not an interoperable TURN implementation.
#
#              Not yet mapped to rules: it serves as a labeled protocol baseline for STUN/TURN detections.

import logging
import queue
import socket
import threading

from .. import OSType, RtaParameter, register_multihost_rta
from .._multihost import MultiHostError, RoleContext, StdinCoordinator
from .._protocols.stun.harness import MAX_ECHO_BYTES, ServerSession, SessionConfig, Task, parse_command, run_client
from .._protocols.stun.transports import DEFAULT_PORTS, TRANSPORTS, TransportName, connect, open_listener

log = logging.getLogger(__name__)

TASK_ALIASES = {"ping": "ping", "echo": "echo", "status": "get_status"}

rta = register_multihost_rta(
    id="83e2ebbb-1507-4a00-b4ab-ae0336740d2b",
    name="stun_turn_channel",
    platforms=[OSType.LINUX, OSType.MACOS],
    techniques=["T1071", "T1573"],
    parameters=[
        RtaParameter(
            "transport",
            "udp",
            choices=list(TRANSPORTS),
            help="udp: cleartext; tls: PSK-encrypted (stdlib on Python 3.13+, python-mbedtls on 3.12); "
            "dtls: PSK-encrypted, needs python-mbedtls on Python 3.12 (cortado[protocols])",
        ),
        RtaParameter("tasks", "ping,echo,status", help="Comma-separated tasks sent each round (ping, echo, status)"),
        RtaParameter("rounds", "3", help="Number of times the task list is sent"),
        RtaParameter("interval", "2", help="Seconds between tasks; the server keeps answering keepalives meanwhile"),
        RtaParameter("echo_text", "cortado multihost rta", help=f"Text for echo tasks, at most {MAX_ECHO_BYTES} bytes"),
        RtaParameter("keepalive", "10", help="Seconds between client Binding refreshes, 0 disables them"),
        RtaParameter("client_id", "lab_client", help="Client identifier carried in registrations"),
        RtaParameter("max_skew", "60", help="Maximum payload age in seconds (tolerated clock skew between hosts)"),
        RtaParameter(
            "interactive",
            "false",
            choices=["false", "true"],
            help="Server reads `ping | echo TEXT | status | quit` from the console instead of sending the task list",
        ),
    ],
)


def _session_config(ctx: RoleContext) -> SessionConfig:
    transport: TransportName = ctx.param("transport")  # type: ignore[assignment]  # validated by choices
    return SessionConfig(transport=transport, secret=ctx.secret, max_age_secs=ctx.param_float("max_skew"))


def _task_plan(ctx: RoleContext) -> list[Task]:
    tasks: list[Task] = []
    for name in (n.strip() for n in ctx.param("tasks").split(",")):
        if name not in TASK_ALIASES:
            raise MultiHostError(f"Unknown task `{name}`, choose from: {', '.join(TASK_ALIASES)}")
        if name == "echo":
            text = ctx.param("echo_text")
            if len(text.encode("utf-8")) > MAX_ECHO_BYTES:
                raise MultiHostError(f"`echo_text` exceeds {MAX_ECHO_BYTES} bytes")
            tasks.append(Task("echo", {"text": text}))
        else:
            tasks.append(Task(TASK_ALIASES[name]))
    return tasks


def _interactive_loop(ctx: RoleContext, session: ServerSession) -> None:
    commands: queue.Queue[str] = queue.Queue()

    def read_commands() -> None:
        while True:
            try:
                commands.put(input("stun-research-server> ").strip())
            except EOFError:
                commands.put("quit")
                return

    threading.Thread(target=read_commands, daemon=True).start()
    print("commands: ping | echo TEXT | status | quit", flush=True)
    while ctx.remaining() > 0:
        try:
            line = commands.get_nowait()
        except queue.Empty:
            session.idle(0.5, ctx.deadline)
            continue
        if line in ("quit", "exit"):
            return
        task = parse_command(line)
        if task is None:
            print("invalid command; use ping | echo TEXT | status | quit", flush=True)
            continue
        _ = session.run_task(task, ctx.deadline)


@rta.role("server", listens=True)
def server(ctx: RoleContext) -> None:
    """Binds the STUN/TURN-like listener, waits for the client, and sends the task plan"""
    config = _session_config(ctx)
    interactive = ctx.param_bool("interactive")
    if interactive and not (isinstance(ctx.coordinator, StdinCoordinator) and ctx.coordinator.mode != "driven"):
        raise MultiHostError("`interactive=true` needs an operator console; it can't be used with --local or --driven")
    tasks = _task_plan(ctx)
    rounds = ctx.param_int("rounds")
    interval = ctx.param_float("interval")

    listener = open_listener(config.transport, ctx.bind_address(DEFAULT_PORTS[config.transport]), ctx.secret)
    try:
        bound_host, bound_port = listener.address
        ctx.ready(port=bound_port, bind=bound_host, transport=config.transport)
        channel, peer = listener.accept(ctx.remaining())
        ctx.event("session_established", peer=list(peer), transport=config.transport)

        session = ServerSession(channel, peer, config, ctx.event)
        try:
            _ = session.wait_for_registration(ctx.deadline)
            if interactive:
                _interactive_loop(ctx, session)
                return
            for round_number in range(rounds):
                for task in tasks:
                    result = session.run_task(task, ctx.deadline)
                    if not result["ok"]:
                        raise RuntimeError(f"Client rejected task `{task.action}` in round {round_number + 1}")
                    session.idle(interval, ctx.deadline)
        finally:
            session.close()
    finally:
        listener.close()


@rta.role("client")
def client(ctx: RoleContext) -> None:
    """Connects to the server, registers, and answers allowlisted tasks until the server closes the session"""
    config = _session_config(ctx)
    host, port = ctx.peer_address(DEFAULT_PORTS[config.transport])
    address = (socket.gethostbyname(host), port)

    channel = connect(config.transport, address, ctx.secret, ctx.remaining())
    ctx.event("session_established", peer=list(address), transport=config.transport)
    try:
        handled = run_client(
            channel,
            address,
            ctx.param("client_id"),
            config,
            ctx.event,
            keepalive_secs=ctx.param_float("keepalive"),
            deadline=ctx.deadline,
        )
    finally:
        channel.close()
    if handled == 0:
        raise RuntimeError("Session closed before any task was handled")
