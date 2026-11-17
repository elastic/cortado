# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Build and emit complete synthetic TCP exchanges on a monitored interface."""

import ipaddress
import logging
import os
import socket
import struct
import time
from collections.abc import Iterable

log = logging.getLogger(__name__)

ETHERTYPE_IPV4 = 0x0800
INTERFACE_ENVIRONMENT_VARIABLE = "CORTADO_NETWORK_INTERFACE"

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_PSH = 0x08
TCP_ACK = 0x10


class SyntheticTcpError(RuntimeError):
    """Raised when a synthetic TCP exchange cannot be built or emitted."""


def _ones_complement_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _build_frame(
    *,
    mac_address: bytes,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    payload: bytes = b"",
    identification: int,
) -> bytes:
    source_bytes = socket.inet_aton(source_ip)
    destination_bytes = socket.inet_aton(destination_ip)

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        64240,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        source_bytes,
        destination_bytes,
        0,
        socket.IPPROTO_TCP,
        len(tcp_header) + len(payload),
    )
    tcp_checksum = _ones_complement_checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        64240,
        tcp_checksum,
        0,
    )

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        20 + len(tcp_header) + len(payload),
        identification,
        0x4000,
        64,
        socket.IPPROTO_TCP,
        0,
        source_bytes,
        destination_bytes,
    )
    ip_checksum = _ones_complement_checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        20 + len(tcp_header) + len(payload),
        identification,
        0x4000,
        64,
        socket.IPPROTO_TCP,
        ip_checksum,
        source_bytes,
        destination_bytes,
    )

    # Addressing the frame to this interface's own MAC keeps the synthetic
    # layer-3 endpoints from being routed to either endpoint.
    ethernet_header = mac_address + mac_address + struct.pack("!H", ETHERTYPE_IPV4)
    return ethernet_header + ip_header + tcp_header + payload


def build_tcp_exchange(
    *,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    mac_address: bytes,
    client_payload: bytes,
    server_payload: bytes,
) -> tuple[bytes, ...]:
    """Build a handshake, bidirectional data exchange, and graceful close."""
    for address in (source_ip, destination_ip):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise SyntheticTcpError(f"Invalid IP address {address!r}") from error
        if parsed.version != 4:
            raise SyntheticTcpError("Synthetic TCP exchanges currently support IPv4 only")
    if source_ip == destination_ip:
        raise SyntheticTcpError("Source and destination IP addresses must differ")
    if not 1 <= source_port <= 65535 or not 1 <= destination_port <= 65535:
        raise SyntheticTcpError("TCP ports must be between 1 and 65535")
    if len(mac_address) != 6:
        raise SyntheticTcpError("Ethernet MAC address must contain exactly 6 bytes")
    if not client_payload or not server_payload:
        raise SyntheticTcpError("Both sides must send payload data")

    client_sequence = 0x10203040
    server_sequence = 0x50607080
    client_data_sequence = client_sequence + 1
    server_data_sequence = server_sequence + 1
    client_after_data = client_data_sequence + len(client_payload)
    server_after_data = server_data_sequence + len(server_payload)

    segment_arguments = (
        (source_ip, destination_ip, source_port, destination_port, client_sequence, 0, TCP_SYN, b""),
        (
            destination_ip,
            source_ip,
            destination_port,
            source_port,
            server_sequence,
            client_data_sequence,
            TCP_SYN | TCP_ACK,
            b"",
        ),
        (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            client_data_sequence,
            server_data_sequence,
            TCP_ACK,
            b"",
        ),
        (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            client_data_sequence,
            server_data_sequence,
            TCP_PSH | TCP_ACK,
            client_payload,
        ),
        (
            destination_ip,
            source_ip,
            destination_port,
            source_port,
            server_data_sequence,
            client_after_data,
            TCP_ACK,
            b"",
        ),
        (
            destination_ip,
            source_ip,
            destination_port,
            source_port,
            server_data_sequence,
            client_after_data,
            TCP_PSH | TCP_ACK,
            server_payload,
        ),
        (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            client_after_data,
            server_after_data,
            TCP_ACK,
            b"",
        ),
        (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            client_after_data,
            server_after_data,
            TCP_FIN | TCP_ACK,
            b"",
        ),
        (
            destination_ip,
            source_ip,
            destination_port,
            source_port,
            server_after_data,
            client_after_data + 1,
            TCP_FIN | TCP_ACK,
            b"",
        ),
        (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            client_after_data + 1,
            server_after_data + 1,
            TCP_ACK,
            b"",
        ),
    )

    return tuple(
        _build_frame(
            mac_address=mac_address,
            source_ip=segment_source_ip,
            destination_ip=segment_destination_ip,
            source_port=segment_source_port,
            destination_port=segment_destination_port,
            sequence=sequence,
            acknowledgement=acknowledgement,
            flags=flags,
            payload=payload,
            identification=0x4000 + index,
        )
        for index, (
            segment_source_ip,
            segment_destination_ip,
            segment_source_port,
            segment_destination_port,
            sequence,
            acknowledgement,
            flags,
            payload,
        ) in enumerate(segment_arguments)
    )


def configured_interface() -> str:
    """Return an explicitly configured or default-route non-loopback interface."""
    configured = os.environ.get(INTERFACE_ENVIRONMENT_VARIABLE, "").strip()
    available = {name for _, name in socket.if_nameindex()}
    if configured:
        if configured not in available:
            raise SyntheticTcpError(f"Network interface {configured!r} does not exist")
        if configured == "lo":
            raise SyntheticTcpError("The loopback interface is not suitable for network-sensor RTAs")
        return configured

    try:
        with open("/proc/net/route", encoding="ascii") as route_table:
            for line in route_table:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 0x2:
                    interface = fields[0]
                    if interface in available and interface != "lo":
                        return interface
    except (OSError, ValueError):
        pass

    non_loopback = sorted(available - {"lo"})
    if len(non_loopback) == 1:
        return non_loopback[0]
    raise SyntheticTcpError(f"Set {INTERFACE_ENVIRONMENT_VARIABLE} to the monitored non-loopback network interface")


def interface_mac_address(interface: str) -> bytes:
    """Read a Linux interface's hardware address."""
    try:
        _ = socket.if_nametoindex(interface)
        with open(f"/sys/class/net/{interface}/address", encoding="ascii") as address_file:
            mac_address = bytes.fromhex(address_file.read().strip().replace(":", ""))
    except (OSError, ValueError) as error:
        raise SyntheticTcpError(f"Unable to read MAC address for interface {interface!r}: {error}") from error
    if len(mac_address) != 6 or mac_address == b"\x00" * 6:
        raise SyntheticTcpError(f"Network interface {interface!r} has no usable Ethernet MAC address")
    return mac_address


def emit_frames(
    frames: Iterable[bytes],
    *,
    interface: str | None = None,
    interval_seconds: float = 0.05,
) -> None:
    """Emit complete Ethernet frames through a monitored physical interface."""
    selected_interface = interface or configured_interface()
    if selected_interface == "lo":
        raise SyntheticTcpError("Refusing to emit network-sensor traffic on loopback")
    frame_list = tuple(frames)
    if len(frame_list) < 2:
        raise SyntheticTcpError("A multi-packet exchange requires at least two frames")

    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_IPV4)) as packet_socket:
            packet_socket.bind((selected_interface, 0))
            for index, frame in enumerate(frame_list):
                bytes_sent = packet_socket.send(frame)
                if bytes_sent != len(frame):
                    raise SyntheticTcpError(
                        f"Raw frame transmission was incomplete: sent {bytes_sent} of {len(frame)} bytes"
                    )
                if index + 1 < len(frame_list):
                    time.sleep(interval_seconds)
    except PermissionError as error:
        raise SyntheticTcpError("Raw packet privileges are required (run as root or with CAP_NET_RAW)") from error
    except OSError as error:
        raise SyntheticTcpError(
            f"Failed to emit synthetic TCP exchange on interface {selected_interface!r}: {error}"
        ) from error

    log.info("Emitted %d TCP frames on interface %s", len(frame_list), selected_interface)
