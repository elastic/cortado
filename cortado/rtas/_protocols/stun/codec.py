# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Strict STUN/TURN message codec for the benign lab harness.

Only STUN Binding messages and TURN-like Data Indications are implemented. This is not a general-purpose TURN
relay or remote administration protocol.
"""

import hashlib
import hmac
import ipaddress
import json
import math
import os
import struct
import time
from dataclasses import dataclass
from typing import Any, Iterable

MAGIC_COOKIE = 0x2112A442
HEADER = struct.Struct("!HHI12s")
ATTRIBUTE_HEADER = struct.Struct("!HH")

BINDING_REQUEST = 0x0001
BINDING_SUCCESS_RESPONSE = 0x0101
DATA_INDICATION = 0x0017

ATTR_DATA = 0x0013
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022

# SOFTWARE attribute values match the standalone research harnesses so captures stay comparable
SOFTWARE_CLEARTEXT = b"safe-stun-turn-research/1.0"
SOFTWARE_ENCRYPTED = b"safe-encrypted-stun-research/1.0"

MAX_MESSAGE_SIZE = 4096
MAX_PAYLOAD_SIZE = 2048
DEFAULT_MAX_PAYLOAD_AGE_SECS = 60
ALLOWED_ACTIONS = frozenset({"ping", "echo", "get_status"})


class ProtocolError(ValueError):
    """Raised when a message violates the constrained lab protocol."""


@dataclass(frozen=True)
class StunMessage:
    message_type: int
    transaction_id: bytes
    attributes: tuple[tuple[int, bytes], ...]

    def get_attribute(self, attribute_type: int) -> bytes | None:
        """Return the first value for an attribute type."""
        for current_type, value in self.attributes:
            if current_type == attribute_type:
                return value
        return None


def encode_message(
    message_type: int,
    attributes: Iterable[tuple[int, bytes]] = (),
    transaction_id: bytes | None = None,
) -> bytes:
    """Encode a validated STUN message and its attributes."""
    if transaction_id is None:
        transaction_id = os.urandom(12)
    if len(transaction_id) != 12:
        raise ProtocolError("transaction ID must be 12 bytes")
    if message_type & 0xC000:
        raise ProtocolError("the two most significant STUN type bits must be zero")

    body = bytearray()
    for attribute_type, value in attributes:
        if len(value) > MAX_PAYLOAD_SIZE:
            raise ProtocolError("attribute exceeds the lab size limit")
        body.extend(ATTRIBUTE_HEADER.pack(attribute_type, len(value)))
        body.extend(value)
        body.extend(b"\x00" * ((-len(value)) % 4))
    if len(body) > 0xFFFF:
        raise ProtocolError("STUN body is too large")
    return HEADER.pack(message_type, len(body), MAGIC_COOKIE, transaction_id) + body


def decode_message(data: bytes) -> StunMessage:
    """Decode and strictly validate one STUN message."""
    if len(data) < HEADER.size or len(data) > MAX_MESSAGE_SIZE:
        raise ProtocolError("invalid STUN message size")
    message_type, body_length, cookie, transaction_id = HEADER.unpack_from(data)
    if message_type & 0xC000:
        raise ProtocolError("invalid STUN message type")
    if cookie != MAGIC_COOKIE:
        raise ProtocolError("invalid STUN magic cookie")
    if body_length % 4 or len(data) != HEADER.size + body_length:
        raise ProtocolError("invalid STUN body length")

    attributes: list[tuple[int, bytes]] = []
    offset = HEADER.size
    while offset < len(data):
        if offset + ATTRIBUTE_HEADER.size > len(data):
            raise ProtocolError("truncated STUN attribute")
        attribute_type, value_length = ATTRIBUTE_HEADER.unpack_from(data, offset)
        offset += ATTRIBUTE_HEADER.size
        padded_length = value_length + ((-value_length) % 4)
        if offset + padded_length > len(data):
            raise ProtocolError("truncated STUN attribute value")
        attributes.append((attribute_type, data[offset : offset + value_length]))
        offset += padded_length
    return StunMessage(message_type, transaction_id, tuple(attributes))


def expected_message_size(header: bytes) -> int:
    """Return total STUN size from an already received 20-byte stream header."""
    if len(header) != HEADER.size:
        raise ProtocolError("a complete STUN header is required")
    _, body_length, cookie, _ = HEADER.unpack(header)
    if cookie != MAGIC_COOKIE or body_length % 4:
        raise ProtocolError("invalid STUN stream header")
    total = HEADER.size + body_length
    if total > MAX_MESSAGE_SIZE:
        raise ProtocolError("STUN stream message exceeds the lab limit")
    return total


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Serialize a payload into stable UTF-8 JSON bytes."""
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("payload is not JSON serializable") from exc


def sign_payload(payload: dict[str, Any], secret: bytes) -> dict[str, Any]:
    """Return a payload carrying an HMAC-SHA256 signature."""
    if not secret:
        raise ProtocolError("a non-empty shared secret is required")
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    signed = dict(unsigned)
    signed["signature"] = hmac.new(secret, _canonical_json(unsigned), hashlib.sha256).hexdigest()
    return signed


def verify_payload(
    encoded: bytes, secret: bytes, max_age_secs: float = DEFAULT_MAX_PAYLOAD_AGE_SECS
) -> dict[str, Any]:
    """Authenticate and freshness-check an encoded payload.

    `max_age_secs` also bounds tolerated clock skew between the two lab hosts.
    """
    if not secret:
        raise ProtocolError("a non-empty shared secret is required")
    if len(encoded) > MAX_PAYLOAD_SIZE:
        raise ProtocolError("application payload is too large")
    try:
        payload = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("payload is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("payload must be a JSON object")
    payload_dict: dict[str, Any] = payload  # type: ignore[assignment]

    signature = payload_dict.get("signature")
    if not isinstance(signature, str):
        raise ProtocolError("payload has no signature")
    unsigned = dict(payload_dict)
    unsigned.pop("signature")
    expected = hmac.new(secret, _canonical_json(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ProtocolError("payload signature is invalid")

    timestamp = payload_dict.get("timestamp")
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool) or not math.isfinite(timestamp):
        raise ProtocolError("payload has no valid timestamp")
    if abs(time.time() - float(timestamp)) > max_age_secs:
        raise ProtocolError("payload timestamp is outside the allowed window (check host clock sync)")
    return payload_dict


def encode_payload_message(message_type: int, payload: dict[str, Any], secret: bytes, software: bytes) -> bytes:
    """Encode a signed payload inside a STUN/TURN message."""
    encoded = _canonical_json(sign_payload(payload, secret))
    if len(encoded) > MAX_PAYLOAD_SIZE:
        raise ProtocolError("signed payload is too large")
    return encode_message(message_type, ((ATTR_DATA, encoded), (ATTR_SOFTWARE, software)))


def decode_payload_message(
    message: StunMessage,
    expected_type: int,
    secret: bytes,
    max_age_secs: float = DEFAULT_MAX_PAYLOAD_AGE_SECS,
) -> dict[str, Any]:
    """Decode and authenticate a typed STUN/TURN payload."""
    if message.message_type != expected_type:
        raise ProtocolError("unexpected STUN/TURN message type")
    data = message.get_attribute(ATTR_DATA)
    if data is None:
        raise ProtocolError("message has no DATA attribute")
    return verify_payload(data, secret, max_age_secs)


def encode_xor_mapped_address(host: str, port: int) -> bytes:
    """Encode an IPv4 XOR-MAPPED-ADDRESS attribute value."""
    if not 0 <= port <= 65535:
        raise ProtocolError("mapped port must be between 0 and 65535")
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as exc:
        raise ProtocolError("mapped address must be IPv4") from exc
    return struct.pack("!BBHI", 0, 0x01, port ^ (MAGIC_COOKIE >> 16), int(address) ^ MAGIC_COOKIE)


def decode_xor_mapped_address(value: bytes) -> tuple[str, int]:
    """Decode an IPv4 XOR-MAPPED-ADDRESS attribute value."""
    if len(value) != 8:
        raise ProtocolError("only IPv4 XOR-MAPPED-ADDRESS values are supported")
    _, family, x_port, x_address = struct.unpack("!BBHI", value)
    if family != 0x01:
        raise ProtocolError("only IPv4 XOR-MAPPED-ADDRESS values are supported")
    return str(ipaddress.IPv4Address(x_address ^ MAGIC_COOKIE)), x_port ^ (MAGIC_COOKIE >> 16)
