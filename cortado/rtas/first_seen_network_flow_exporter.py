# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: First Seen Network Flow Exporter
# RTA: first_seen_network_flow_exporter.py
# Description: Emits telemetry for both "First Seen Network Flow Exporter" (BBR)
#              and "First Seen Network Flow Exporter Followed by Suspicious
#              Source Activity" (higher-order).
#
#              1. Sends one NetFlow v5 packet to the Elastic NetFlow integration
#                 (UDP/2055) from a randomized public exporter address so
#                 observer.ip is unique in the BBR's 14-day new-terms window.
#              2. Then spoofs inbound RDP (TCP/3389) from that same exporter IP
#                 to an internal host so a medium-or-higher query alert is
#                 created with source.ip equal to the BBR observer.ip. The
#                 higher-order EQL sequence joins those two alerts within 30m.
#
#              NetFlow v5 is used because it is a fixed record format and does
#              not require a prior template. The exporter address is assigned
#              to lo so the UDP export is a real datagram the collector can
#              accept; observer.ip is that UDP source, not the addresses inside
#              the flow record.
#
#              The RDP SYN is forged with a public source so it is not excluded
#              as reserved/documentation space. The higher-order rule ignores
#              new_terms, threat_match, and machine_learning alerts, so RDP
#              from the Internet (query, risk_score 47) is used as the second
#              event.
#
#              Requires root: lo address add/delete and CAP_NET_RAW. Run on a
#              host where Elastic Agent's NetFlow integration listens on
#              127.0.0.1:2055 and a network sensor (Packetbeat / network_traffic)
#              can observe the forged RDP flow. Enable the BBR, the higher-order
#              rule, and "RDP (Remote Desktop Protocol) from the Internet".

import logging
import os
import random
import socket
import struct
import subprocess
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

NETFLOW_HOST = "127.0.0.1"
NETFLOW_PORT = 2055

FLOW_SRC_IP = "192.0.2.1"
FLOW_DST_IP = "192.0.2.2"

RDP_PORT = 3389
PRIVATE_RDP_DEST_IP = "10.10.10.10"

BBR_RULE_ID = "dfe3f626-4224-417e-aff1-8ef9a72c3191"
HIGHER_ORDER_RULE_ID = "882c8edc-1e39-4a60-80b2-485491b6c91c"
RDP_FROM_INTERNET_RULE_ID = "8c1bdde8-4204-45c0-9e0c-c85ca3902488"


def _netflow_v5_packet() -> bytes:
    """Build a single-record NetFlow v5 packet matching Filebeat's v5 layout."""
    uptime_ms = 60_000
    header = struct.pack(
        "!HHIIIIBBH",
        5,
        1,
        uptime_ms,
        int(time.time()),
        0,
        random.randint(1, 0x7FFFFFFF),
        0,
        0,
        0,
    )
    # Filebeat v5 record order after ports: pad, tcp_flags, protocol, ToS.
    record = struct.pack(
        "!4s4s4sHHIIIIHHBBBBHHBBH",
        socket.inet_aton(FLOW_SRC_IP),
        socket.inet_aton(FLOW_DST_IP),
        socket.inet_aton("0.0.0.0"),
        1,
        2,
        10,
        1500,
        uptime_ms - 1_000,
        uptime_ms,
        54321,
        443,
        0,
        0x18,
        6,
        0,
        0,
        0,
        24,
        24,
        0,
    )
    packet = header + record
    if len(packet) != 72:
        raise ValueError(f"NetFlow v5 packet length {len(packet)} != 72")
    return packet


def _exporter_ip() -> str:
    """Pick a public exporter IP outside the RDP rule's reserved-range exclusions."""
    return f"9.9.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _add_loopback_ip(ip: str) -> bool:
    """Assign ip/32 to lo so the NetFlow export can bind that source address."""
    completed = subprocess.run(
        ["ip", "addr", "add", f"{ip}/32", "dev", "lo"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0 or "File exists" in completed.stderr:
        return True
    log.error("Failed to add %s to lo: %s", ip, completed.stderr.strip())
    return False


def _delete_loopback_ip(ip: str) -> None:
    _ = subprocess.run(
        ["ip", "addr", "del", f"{ip}/32", "dev", "lo"],
        check=False,
        capture_output=True,
    )


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += s >> 16
    return ~s & 0xFFFF


def _rdp_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build a raw IP/TCP SYN packet for inbound RDP from the exporter IP."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    seq = random.randint(0, 0xFFFFFFFF)
    data_offset = 5 << 4
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        0,
        data_offset,
        0x02,
        8192,
        0,
        0,
    )
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_checksum = _ones_complement_sum(pseudo + tcp_header)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        0,
        data_offset,
        0x02,
        8192,
        tcp_checksum,
        0,
    )

    ip_total_len = 20 + len(tcp_header)
    ident = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        ident,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        src_bytes,
        dst_bytes,
    )
    ip_checksum = _ones_complement_sum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        ident,
        0,
        64,
        socket.IPPROTO_TCP,
        ip_checksum,
        src_bytes,
        dst_bytes,
    )
    return ip_header + tcp_header


def _send_netflow(exporter_ip: str) -> bool:
    packet = _netflow_v5_packet()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            sock.bind((exporter_ip, 0))
        except OSError as e:
            log.error("Could not bind NetFlow exporter address %s: %s", exporter_ip, e)
            return False
        log.info(
            "Sending NetFlow v5 export from observer.ip=%s to %s:%d",
            exporter_ip,
            NETFLOW_HOST,
            NETFLOW_PORT,
        )
        _ = sock.sendto(packet, (NETFLOW_HOST, NETFLOW_PORT))
        log.info("Sent NetFlow v5 record %s -> %s via exporter %s", FLOW_SRC_IP, FLOW_DST_IP, exporter_ip)
        return True
    finally:
        sock.close()


def _send_rdp_from_exporter(exporter_ip: str) -> None:
    src_port = random.randint(1024, 65535)
    packet = _rdp_syn_packet(exporter_ip, PRIVATE_RDP_DEST_IP, src_port, RDP_PORT)
    log.info(
        "Sending spoofed RDP SYN %s:%d -> %s:%d (source.ip must equal exporter observer.ip)",
        exporter_ip,
        src_port,
        PRIVATE_RDP_DEST_IP,
        RDP_PORT,
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        _ = sock.sendto(packet, (PRIVATE_RDP_DEST_IP, RDP_PORT))
        log.info("Spoofed RDP SYN emitted from exporter %s", exporter_ip)
    except OSError as e:
        log.error("Failed to send spoofed RDP SYN: %s", e)
    finally:
        sock.close()


@register_code_rta(
    id="5af5bad1-b60f-4b48-900c-46d099ac6bbb",
    name="first_seen_network_flow_exporter",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id=BBR_RULE_ID,
            name="First Seen Network Flow Exporter",
        ),
        RuleMetadata(
            id=HIGHER_ORDER_RULE_ID,
            name="First Seen Network Flow Exporter Followed by Suspicious Source Activity",
        ),
        RuleMetadata(
            id=RDP_FROM_INTERNET_RULE_ID,
            name="RDP (Remote Desktop Protocol) from the Internet",
        ),
    ],
    techniques=["T1562", "T1021", "T1021.001", "T1133", "T1190"],
)
def main() -> None:
    """Export NetFlow from a first-seen public exporter, then RDP from that same IP."""
    if os.geteuid() != 0:
        log.error("Root is required to assign the exporter IP on lo and send a spoofed RDP SYN")
        return

    exporter_ip = _exporter_ip()
    if not _add_loopback_ip(exporter_ip):
        return

    try:
        if not _send_netflow(exporter_ip):
            return
        # Keep original-event timestamps ordered for the higher-order EQL sequence.
        time.sleep(2)
        _send_rdp_from_exporter(exporter_ip)
    finally:
        _delete_loopback_ip(exporter_ip)
