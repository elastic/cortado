# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential Redis Lua Use-After-Free RCE Attempt (CVE-2025-49844 / RediShell)
# RTA: network_redis_lua_use_after_free_rce.py
# Description: Emulates the CVE-2025-49844 (RediShell) exploit signature by
#              binding a minimal RESP server on TCP/6379 and connecting to it
#              via the host's non-loopback IP, then sending a Redis EVAL command
#              whose Lua script contains string.rep() and collectgarbage().
#              Packetbeat / network_traffic with the Redis module enabled decodes
#              the exchange and populates network_traffic.redis.query with the
#              full EVAL payload, satisfying all three like~ wildcard conditions
#              in the rule (EVAL, string.rep, collectgarbage).
#
#              TCP/6379 is unprivileged so no special capabilities are required.
#              The connection is made to the host's non-loopback IP so the
#              traffic traverses the physical NIC where Packetbeat captures.
#              If port 6379 is already in use (live Redis instance), the bind
#              will fail and the RTA will exit — connect directly to the live
#              instance if that scenario is encountered.

import logging
import socket
import threading
import time

from . import OSType, RuleMetadata, register_code_rta
from ._common import get_host_ip

log = logging.getLogger(__name__)

REDIS_PORT = 6379

# Minimal CVE-2025-49844 Lua payload: string.rep() + collectgarbage() inside EVAL.
_LUA_SCRIPT = "local x = string.rep('A', 1); collectgarbage('collect'); return 1"
_REDIS_EVAL_COMMAND = (
    f"*3\r\n"
    f"$4\r\nEVAL\r\n"
    f"${len(_LUA_SCRIPT)}\r\n{_LUA_SCRIPT}\r\n"
    f"$1\r\n0\r\n"
).encode()

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
    id="870eab97-d467-4783-a955-9e67a14432eb",
    name="network_redis_lua_use_after_free_rce",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="9a1ba0ac-aa6f-4c0d-8c80-b7f6ea2efa36",
            name="Potential Redis Lua Use-After-Free RCE Attempt (CVE-2025-49844 / RediShell)",
        )
    ],
    techniques=["T1190", "T1059", "T1059.011"],
)
def main() -> None:
    """Send a Redis EVAL with the CVE-2025-49844 Lua exploit signature to a fake RESP server."""
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
        "Sending Redis EVAL (CVE-2025-49844 / RediShell signature) to %s:%d",
        local_ip, REDIS_PORT,
    )
    try:
        conn = socket.create_connection((local_ip, REDIS_PORT), timeout=5)
        try:
            conn.sendall(_REDIS_EVAL_COMMAND)
            resp = conn.recv(256)
            log.info("Server response: %s", resp)
        except OSError as e:
            log.error("Redis client error: %s", e)
        finally:
            conn.close()
    except OSError as e:
        log.error("Could not connect to %s:%d: %s", local_ip, REDIS_PORT, e)

    thread.join(timeout=5)
