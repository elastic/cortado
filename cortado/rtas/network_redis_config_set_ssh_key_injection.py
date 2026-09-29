# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential Redis CONFIG SET SSH Authorized Key Injection
# RTA: network_redis_config_set_ssh_key_injection.py
# Description: Emulates the Redis SSH authorized key injection technique by
#              binding a minimal RESP server on TCP/6379 and connecting via the
#              host's non-loopback IP, then sending a Redis CONFIG SET dir
#              /root/.ssh command. Packetbeat / network_traffic with the Redis
#              module enabled decodes the exchange and populates
#              network_traffic.redis.query with the full command, satisfying the
#              first branch of the rule's OR condition:
#              "*CONFIG SET dir*" and "*/.ssh*".
#
#              TCP/6379 is unprivileged so no special capabilities are required.
#              The connection is made to the host's non-loopback IP so the
#              traffic traverses the physical NIC where Packetbeat captures.

import logging
import socket
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

REDIS_PORT = 6379

# CONFIG SET dir /root/.ssh — satisfies "*CONFIG SET dir*" and "*/.ssh*"
_CONFIG_SET_COMMAND = (
    b"*4\r\n"
    b"$6\r\nCONFIG\r\n"
    b"$3\r\nSET\r\n"
    b"$3\r\ndir\r\n"
    b"$10\r\n/root/.ssh\r\n"
)

_RESP_OK = b"+OK\r\n"


def _serve_one_request(server: socket.socket, ready: threading.Event) -> None:
    ready.set()
    try:
        conn, addr = server.accept()
        log.debug("Accepted connection from %s", addr)
        try:
            _ = conn.recv(4096)
            conn.sendall(_RESP_OK)
        except OSError as e:
            log.debug("Connection handler error: %s", e)
        finally:
            conn.close()
    except OSError as e:
        log.debug("Server accept error: %s", e)
    finally:
        server.close()


@register_code_rta(
    id="43bc66fb-b392-4737-8d09-841b90df4a9e",
    name="network_redis_config_set_ssh_key_injection",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="39ab0f66-efa0-4649-9c9c-8c64682f5fdd",
            name="Potential Redis CONFIG SET SSH Authorized Key Injection",
        )
    ],
    techniques=["T1098", "T1098.004", "T1190"],
)
def main() -> None:
    """Send a Redis CONFIG SET dir /root/.ssh to a fake RESP server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", REDIS_PORT))
    except OSError as e:
        log.error("Could not bind 0.0.0.0:%d (%s)", REDIS_PORT, e)
        return
    server.listen(1)

    ready = threading.Event()
    thread = threading.Thread(target=_serve_one_request, args=(server, ready), daemon=True)
    thread.start()

    if not ready.wait(timeout=5):
        log.error("Listener on TCP/%d did not start in time", REDIS_PORT)
        return

    time.sleep(0.1)

    local_ip = get_host_ip()
    log.info(
        "Sending Redis CONFIG SET dir /root/.ssh (SSH key injection signature) to %s:%d",
        local_ip, REDIS_PORT,
    )
    try:
        conn = socket.create_connection((local_ip, REDIS_PORT), timeout=5)
        try:
            conn.sendall(_CONFIG_SET_COMMAND)
            resp = conn.recv(256)
            log.info("Server response: %s", resp)
        except OSError as e:
            log.error("Redis client error: %s", e)
        finally:
            conn.close()
    except OSError as e:
        log.error("Could not connect to %s:%d: %s", local_ip, REDIS_PORT, e)

    thread.join(timeout=5)
