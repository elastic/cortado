# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Time Seen RMM Service Hostname from Network DNS
# RTA: command_and_control_first_seen_rmm_network_domain.py
# Description: Completes a local DNS A-record transaction for an exact Atera
#              service hostname. A randomized loopback client address creates
#              a new source/registered-domain pair for the rule's seven-day
#              history window. Packetbeat / network_traffic.dns decoding of the
#              UDP/53 exchange supplies the DNS and source fields used by the
#              rule.
#
#              Requires root or CAP_NET_BIND_SERVICE to bind UDP/53. No
#              recursive resolver or RMM service is contacted.

import logging
import random
import socket
import struct
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

DNS_PORT = 53
SERVER_IP = "127.0.0.1"
QUESTION_NAME = "agent-api.atera.com"
ANSWER_IP = "203.0.113.80"
ANSWER_TTL_SECONDS = 60
SOCKET_TIMEOUT_SECONDS = 5

_DNS_TYPE_A = 1
_DNS_CLASS_IN = 1
_DNS_QUERY_FLAGS = 0x0100
_DNS_RESPONSE_FLAGS = 0x8180
_DNS_NAME_POINTER = 0xC00C


def _encode_dns_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        label_bytes = label.encode()
        encoded += bytes([len(label_bytes)]) + label_bytes
    return encoded + b"\x00"


def _dns_question() -> bytes:
    return struct.pack("!HH", _DNS_TYPE_A, _DNS_CLASS_IN)


def _dns_header(message_id: int, flags: int, answer_count: int) -> bytes:
    return struct.pack("!HHHHHH", message_id, flags, 1, answer_count, 0, 0)


def _dns_query(message_id: int) -> bytes:
    return _dns_header(message_id, _DNS_QUERY_FLAGS, 0) + _encode_dns_name(QUESTION_NAME) + _dns_question()


def _dns_response(message_id: int) -> bytes:
    answer = struct.pack(
        "!HHHIH4s",
        _DNS_NAME_POINTER,
        _DNS_TYPE_A,
        _DNS_CLASS_IN,
        ANSWER_TTL_SECONDS,
        4,
        socket.inet_aton(ANSWER_IP),
    )
    return (
        _dns_header(message_id, _DNS_RESPONSE_FLAGS, 1)
        + _encode_dns_name(QUESTION_NAME)
        + _dns_question()
        + answer
    )


@register_code_rta(
    id="62a7f013-2621-4489-9197-700ff9c4c23b",
    name="command_and_control_first_seen_rmm_network_domain",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="e73f0535-781b-4a3b-9042-5d993938f8d9",
            name="First Time Seen RMM Service Hostname from Network DNS",
        )
    ],
    techniques=["T1219", "T1219.002"],
)
def main() -> None:
    """Complete one local RMM DNS transaction from a randomized client address."""
    client_ip = f"127.200.{random.randint(1, 254)}.{random.randint(1, 254)}"
    message_id = random.randint(1, 0xFFFF)
    query = _dns_query(message_id)
    response = _dns_response(message_id)

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.settimeout(SOCKET_TIMEOUT_SECONDS)
    client.settimeout(SOCKET_TIMEOUT_SECONDS)

    try:
        try:
            server.bind((SERVER_IP, DNS_PORT))
        except OSError as error:
            log.error("Unable to bind local DNS responder to %s:%d: %s", SERVER_IP, DNS_PORT, error)
            return

        client.bind((client_ip, 0))
        log.info("Completing local DNS transaction for %s from new client %s", QUESTION_NAME, client_ip)

        _ = client.sendto(query, (SERVER_IP, DNS_PORT))
        received_query, client_address = server.recvfrom(4096)
        if received_query != query:
            raise RuntimeError("Local DNS responder received an unexpected request")

        _ = server.sendto(response, client_address)
        received_response, _ = client.recvfrom(4096)
        if received_response != response:
            raise RuntimeError("Local DNS client received an unexpected response")

        time.sleep(0.05)
    finally:
        client.close()
        server.close()
