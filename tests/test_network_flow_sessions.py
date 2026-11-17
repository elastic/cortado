# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import socket
import struct
from unittest.mock import patch

import pytest

from cortado.rtas import linux_rpc_to_internet, linux_vnc_from_internet
from cortado.rtas._synthetic_tcp import SyntheticTcpError, build_tcp_exchange, configured_interface

TEST_MAC = bytes.fromhex("001122334455")


def _decode_frame(frame: bytes) -> dict[str, object]:
    source_port, destination_port, sequence, acknowledgement, _, flags = struct.unpack("!HHIIBB", frame[34:48])
    total_length = struct.unpack("!H", frame[16:18])[0]
    return {
        "ethernet_destination": frame[:6],
        "ethernet_source": frame[6:12],
        "ethertype": struct.unpack("!H", frame[12:14])[0],
        "source_ip": socket.inet_ntoa(frame[26:30]),
        "destination_ip": socket.inet_ntoa(frame[30:34]),
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence": sequence,
        "acknowledgement": acknowledgement,
        "flags": flags,
        "payload": frame[54 : 14 + total_length],
    }


@pytest.mark.parametrize(
    ("module", "source_ip", "destination_ip", "destination_port"),
    [
        (
            linux_rpc_to_internet,
            linux_rpc_to_internet.PRIVATE_SOURCE_IP,
            linux_rpc_to_internet.PUBLIC_DESTINATION_IP,
            linux_rpc_to_internet.RPC_PORT,
        ),
        (
            linux_vnc_from_internet,
            linux_vnc_from_internet.PUBLIC_SOURCE_IP,
            linux_vnc_from_internet.PRIVATE_DESTINATION_IP,
            linux_vnc_from_internet.VNC_PORT,
        ),
    ],
)
def test_rta_emits_complete_established_session(module, source_ip, destination_ip, destination_port):
    with (
        patch.object(module, "configured_interface", return_value="eth0"),
        patch.object(module, "interface_mac_address", return_value=TEST_MAC),
        patch.object(module.random, "randint", return_value=54321),
        patch.object(module, "emit_frames") as emit_frames,
    ):
        module.main()

    frames = emit_frames.call_args.args[0]
    segments = [_decode_frame(frame) for frame in frames]

    assert len(segments) == 10
    assert segments[0]["source_ip"] == source_ip
    assert segments[0]["destination_ip"] == destination_ip
    assert segments[0]["source_port"] == 54321
    assert segments[0]["destination_port"] == destination_port
    assert [segment["flags"] for segment in segments] == [
        0x02,
        0x12,
        0x10,
        0x18,
        0x10,
        0x18,
        0x10,
        0x11,
        0x11,
        0x10,
    ]
    assert all(not segment["flags"] & 0x04 for segment in segments)
    assert all(segment["ethernet_destination"] == TEST_MAC for segment in segments)
    assert all(segment["ethernet_source"] == TEST_MAC for segment in segments)
    assert all(segment["ethertype"] == 0x0800 for segment in segments)
    assert segments[3]["payload"]
    assert segments[5]["payload"]
    emit_frames.assert_called_once_with(frames, interface="eth0")


def test_tcp_exchange_has_valid_ip_and_tcp_checksums():
    frames = build_tcp_exchange(
        source_ip="10.10.10.10",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=135,
        mac_address=TEST_MAC,
        client_payload=b"request",
        server_payload=b"response",
    )

    for frame in frames:
        ip_header = frame[14:34]
        tcp_segment = frame[34:]
        source_ip = ip_header[12:16]
        destination_ip = ip_header[16:20]
        pseudo_header = struct.pack(
            "!4s4sBBH",
            source_ip,
            destination_ip,
            0,
            socket.IPPROTO_TCP,
            len(tcp_segment),
        )

        assert _checksum(ip_header) == 0
        assert _checksum(pseudo_header + tcp_segment) == 0


def test_configured_interface_rejects_loopback(monkeypatch):
    monkeypatch.setenv("CORTADO_NETWORK_INTERFACE", "lo")
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])

    with pytest.raises(SyntheticTcpError, match="loopback"):
        configured_interface()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF
