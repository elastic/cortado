# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Server and client sessions for the constrained STUN/TURN-like task channel.

The client can only answer `ping`, bounded `echo`, and an in-memory `get_status`. It has no subprocess or shell
execution, file access, dynamic dispatch, persistence, host inventory, or code loading. Every JSON payload is
HMAC-SHA256 signed and freshness-checked, and task request IDs are replay-protected.
"""

import collections
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from .codec import (
    ALLOWED_ACTIONS,
    ATTR_SOFTWARE,
    ATTR_XOR_MAPPED_ADDRESS,
    BINDING_REQUEST,
    BINDING_SUCCESS_RESPONSE,
    DATA_INDICATION,
    DEFAULT_MAX_PAYLOAD_AGE_SECS,
    ProtocolError,
    StunMessage,
    decode_message,
    decode_payload_message,
    decode_xor_mapped_address,
    encode_message,
    encode_payload_message,
    encode_xor_mapped_address,
)
from .transports import SOFTWARE_BY_TRANSPORT, Address, MessageChannel, TransportName

MAX_ECHO_BYTES = 256
MAX_REPLAY_CACHE = 256
REGISTRATION_RETRY_SECS = 1.0
POLL_INTERVAL_SECS = 0.5

SERVICE_NAMES: dict[TransportName, str] = {
    "udp": "safe-stun-turn-research-client",
    "tls": "safe-encrypted-stun-research-client",
    "dtls": "safe-encrypted-stun-research-client",
}


class EventSink(Protocol):
    """Receives structured ground-truth events."""

    def __call__(self, event: str, /, **fields: Any) -> None: ...


@dataclass(frozen=True)
class Task:
    action: str
    arguments: dict[str, Any] = field(default_factory=dict[str, Any])


@dataclass(frozen=True)
class SessionConfig:
    transport: TransportName
    secret: bytes
    max_age_secs: float = DEFAULT_MAX_PAYLOAD_AGE_SECS

    @property
    def software(self) -> bytes:
        return SOFTWARE_BY_TRANSPORT[self.transport]


def _stun_type(message_type: int) -> str:
    return f"0x{message_type:04x}"


def _remaining(deadline: float) -> float:
    return deadline - time.monotonic()


def parse_command(line: str) -> Task | None:
    """Parse one command from the fixed console grammar: `ping`, `status`, or `echo TEXT`."""
    command, _, remainder = line.strip().partition(" ")
    if command == "ping" and not remainder:
        return Task("ping")
    if command == "status" and not remainder:
        return Task("get_status")
    if command == "echo" and remainder:
        if len(remainder.encode("utf-8")) > MAX_ECHO_BYTES:
            raise ProtocolError(f"echo text exceeds {MAX_ECHO_BYTES} bytes")
        return Task("echo", {"text": remainder})
    return None


def perform_action(action: str, arguments: dict[str, Any], started_at: float, service: str) -> dict[str, Any]:
    """Perform only deterministic in-memory operations, never host actions."""
    if action not in ALLOWED_ACTIONS:
        raise ProtocolError("task action is not allowlisted")
    if action == "ping":
        if arguments:
            raise ProtocolError("ping does not accept arguments")
        return {"reply": "pong"}
    if action == "echo":
        if set(arguments) != {"text"}:
            raise ProtocolError("echo accepts only a text argument")
        text = arguments.get("text")
        if not isinstance(text, str):
            raise ProtocolError("echo requires a text string")
        if len(text.encode("utf-8")) > MAX_ECHO_BYTES:
            raise ProtocolError(f"echo text exceeds {MAX_ECHO_BYTES} bytes")
        return {"text": text}
    if action == "get_status":
        if arguments:
            raise ProtocolError("get_status does not accept arguments")
        return {"state": "ok", "service": service, "uptime_seconds": round(time.monotonic() - started_at, 1)}
    raise ProtocolError("unreachable action")


def _validate_client_id(client_id: Any) -> str:
    if not isinstance(client_id, str) or not client_id.isidentifier() or len(client_id) > 64:
        raise ProtocolError("client ID must be a valid identifier of at most 64 characters")
    return client_id


class ServerSession:
    """Server side of one registered client session."""

    def __init__(self, channel: MessageChannel, peer: Address, config: SessionConfig, emit: EventSink):
        self.channel = channel
        self.peer = peer
        self.config = config
        self.emit = emit
        self.client_id: str | None = None

    def _send_binding_success(self, request: StunMessage) -> None:
        payload = decode_payload_message(request, BINDING_REQUEST, self.config.secret, self.config.max_age_secs)
        if payload.get("version") != 1 or payload.get("kind") != "register":
            raise ProtocolError("Binding payload is not a registration")
        client_id = _validate_client_id(payload.get("client_id"))
        if self.client_id is not None and client_id != self.client_id:
            raise ProtocolError("Binding request came from a different client ID")

        # Binding success carries no application HMAC, matching the standalone harnesses
        self.channel.send(
            encode_message(
                BINDING_SUCCESS_RESPONSE,
                (
                    (ATTR_XOR_MAPPED_ADDRESS, encode_xor_mapped_address(*self.peer)),
                    (ATTR_SOFTWARE, self.config.software),
                ),
                transaction_id=request.transaction_id,
            )
        )
        first = self.client_id is None
        self.client_id = client_id
        self.emit(
            "client_registered" if first else "binding_refreshed",
            client_id=client_id,
            peer=list(self.peer),
            stun_type=_stun_type(request.message_type),
        )

    def _next_data_indication(self, deadline: float) -> StunMessage | None:
        """Answer Binding requests until a Data Indication arrives or the deadline passes."""
        while (remaining := _remaining(deadline)) > 0:
            data = self.channel.receive(min(remaining, POLL_INTERVAL_SECS))
            if data is None:
                continue
            try:
                message = decode_message(data)
                if message.message_type == BINDING_REQUEST:
                    self._send_binding_success(message)
                    continue
                if message.message_type == DATA_INDICATION:
                    return message
                raise ProtocolError(f"unexpected STUN type {_stun_type(message.message_type)}")
            except ProtocolError as exc:
                self.emit("message_rejected", peer=list(self.peer), reason=str(exc))
        return None

    def wait_for_registration(self, deadline: float) -> str:
        while self.client_id is None:
            if _remaining(deadline) <= 0:
                raise TimeoutError("client did not register before the deadline")
            message = self._next_data_indication(min(deadline, time.monotonic() + POLL_INTERVAL_SECS))
            if message is not None:
                self.emit("message_rejected", peer=list(self.peer), reason="Data Indication before registration")
        return self.client_id

    def idle(self, seconds: float, deadline: float) -> None:
        """Keep answering Binding keepalives for `seconds` without sending tasks."""
        until = min(deadline, time.monotonic() + seconds)
        while _remaining(until) > 0:
            message = self._next_data_indication(until)
            if message is not None:
                self.emit("message_rejected", peer=list(self.peer), reason="unsolicited Data Indication")

    def run_task(self, task: Task, deadline: float) -> dict[str, Any]:
        """Send one allowlisted task and wait for its matching, authenticated result."""
        if task.action not in ALLOWED_ACTIONS:
            raise ProtocolError("action is not allowlisted")
        if self.client_id is None:
            raise ProtocolError("no client is registered")

        request_id = uuid.uuid4().hex
        self.channel.send(
            encode_payload_message(
                DATA_INDICATION,
                {
                    "version": 1,
                    "kind": "task",
                    "request_id": request_id,
                    "client_id": self.client_id,
                    "action": task.action,
                    "arguments": task.arguments,
                    "timestamp": time.time(),
                },
                self.config.secret,
                self.config.software,
            )
        )
        self.emit(
            "task_sent",
            client_id=self.client_id,
            peer=list(self.peer),
            request_id=request_id,
            action=task.action,
            stun_type=_stun_type(DATA_INDICATION),
        )

        while (message := self._next_data_indication(deadline)) is not None:
            try:
                result = decode_payload_message(message, DATA_INDICATION, self.config.secret, self.config.max_age_secs)
                if (
                    result.get("version") != 1
                    or result.get("kind") != "result"
                    or result.get("client_id") != self.client_id
                    or result.get("request_id") != request_id
                    or result.get("action") != task.action
                    or not isinstance(result.get("ok"), bool)
                    or not isinstance(result.get("result"), dict)
                ):
                    raise ProtocolError("result does not match the outstanding task")
            except ProtocolError as exc:
                self.emit("message_rejected", peer=list(self.peer), reason=str(exc))
                continue
            self.emit(
                "task_result",
                client_id=self.client_id,
                peer=list(self.peer),
                request_id=request_id,
                action=task.action,
                ok=result["ok"],
                result=result["result"],
                stun_type=_stun_type(message.message_type),
            )
            return result
        raise TimeoutError(f"no result for task `{task.action}` before the deadline")

    def close(self) -> None:
        """Tell the client the session is over, then close the channel."""
        if self.client_id is not None:
            try:
                self.channel.send(
                    encode_payload_message(
                        DATA_INDICATION,
                        {"version": 1, "kind": "close", "client_id": self.client_id, "timestamp": time.time()},
                        self.config.secret,
                        self.config.software,
                    )
                )
                self.emit("session_closed", client_id=self.client_id, peer=list(self.peer))
            except OSError as exc:
                self.emit("session_close_failed", client_id=self.client_id, reason=str(exc))
        self.channel.close()


def run_client(
    channel: MessageChannel,
    server: Address,
    client_id: str,
    config: SessionConfig,
    emit: EventSink,
    keepalive_secs: float,
    deadline: float,
) -> int:
    """Register with the server and answer allowlisted tasks until the server closes the session.

    Returns the number of handled tasks. Raises `TimeoutError` if the session is still open at the deadline.
    """
    _ = _validate_client_id(client_id)
    started_at = time.monotonic()
    service = SERVICE_NAMES[config.transport]
    seen_requests: set[str] = set()
    request_order: collections.deque[str] = collections.deque()
    pending_registrations: collections.deque[bytes] = collections.deque(maxlen=8)
    registered = False
    handled = 0
    next_binding = 0.0

    while _remaining(deadline) > 0:
        now = time.monotonic()
        if now >= next_binding:
            registration = encode_payload_message(
                BINDING_REQUEST,
                {"version": 1, "kind": "register", "client_id": client_id, "timestamp": time.time()},
                config.secret,
                config.software,
            )
            pending_registrations.append(decode_message(registration).transaction_id)
            try:
                channel.send(registration)
            except ConnectionRefusedError:
                if registered:
                    raise
            emit("binding_request_sent", client_id=client_id, peer=list(server), stun_type=_stun_type(BINDING_REQUEST))
            interval = keepalive_secs if registered and keepalive_secs > 0 else REGISTRATION_RETRY_SECS
            next_binding = float("inf") if registered and keepalive_secs <= 0 else now + interval

        try:
            data = channel.receive(min(next_binding - time.monotonic(), _remaining(deadline), POLL_INTERVAL_SECS))
        except ConnectionRefusedError:
            # Cleartext UDP: ICMP port unreachable until the server binds
            if registered:
                raise
            time.sleep(POLL_INTERVAL_SECS)
            continue
        if data is None:
            continue

        try:
            message = decode_message(data)
            if message.message_type == BINDING_SUCCESS_RESPONSE:
                if message.transaction_id not in pending_registrations:
                    raise ProtocolError("Binding response has an unknown transaction ID")
                pending_registrations.remove(message.transaction_id)
                mapped = message.get_attribute(ATTR_XOR_MAPPED_ADDRESS)
                emit(
                    "binding_success",
                    client_id=client_id,
                    peer=list(server),
                    mapped_address=list(decode_xor_mapped_address(mapped)) if mapped else None,
                    stun_type=_stun_type(message.message_type),
                )
                if not registered:
                    registered = True
                    next_binding = time.monotonic() + keepalive_secs if keepalive_secs > 0 else float("inf")
                continue

            payload = decode_payload_message(message, DATA_INDICATION, config.secret, config.max_age_secs)
            if payload.get("version") != 1 or payload.get("client_id") != client_id:
                raise ProtocolError("Data Indication is not for this client")
            if payload.get("kind") == "close":
                emit("session_closed", client_id=client_id, peer=list(server), tasks_handled=handled)
                return handled
            if payload.get("kind") != "task":
                raise ProtocolError("Data Indication is not a task")

            request_id = payload.get("request_id")
            if not isinstance(request_id, str) or not request_id:
                raise ProtocolError("task has no request ID")
            if request_id in seen_requests:
                raise ProtocolError("replayed task request ID")
            seen_requests.add(request_id)
            request_order.append(request_id)
            if len(request_order) > MAX_REPLAY_CACHE:
                seen_requests.discard(request_order.popleft())

            action = payload.get("action")
            arguments = payload.get("arguments")
            if not isinstance(action, str):
                raise ProtocolError("task action is invalid")
            try:
                if not isinstance(arguments, dict):
                    raise ProtocolError("task arguments are invalid")
                result = perform_action(action, arguments, started_at, service)  # type: ignore[arg-type]
                ok = True
            except ProtocolError as exc:
                result = {"error": str(exc)}
                ok = False

            channel.send(
                encode_payload_message(
                    DATA_INDICATION,
                    {
                        "version": 1,
                        "kind": "result",
                        "request_id": request_id,
                        "client_id": client_id,
                        "action": action,
                        "ok": ok,
                        "result": result,
                        "timestamp": time.time(),
                    },
                    config.secret,
                    config.software,
                )
            )
            handled += 1
            emit(
                "task_handled",
                client_id=client_id,
                request_id=request_id,
                action=action,
                ok=ok,
                stun_type=_stun_type(message.message_type),
            )
        except ProtocolError as exc:
            emit("message_rejected", peer=list(server), reason=str(exc))

    raise TimeoutError("session was not closed by the server before the deadline")

