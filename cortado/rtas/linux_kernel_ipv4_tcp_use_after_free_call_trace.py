# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Linux Kernel IPv4 TCP Use-After-Free Call Trace
# RTA: linux_kernel_ipv4_tcp_use_after_free_call_trace.py
# Description: Writes two synthetic kernel messages to /dev/kmsg: a KASAN
#              use-after-free diagnostic and an IPv4/TCP call-trace frame.
#              The System integration must collect kernel messages from the
#              host and populate process.name as "kernel".
#
#              This RTA does not exercise a vulnerability or cause a kernel
#              fault. Writing to /dev/kmsg typically requires root.

import logging
import os

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)

KMSG_PATH = "/dev/kmsg"
KERNEL_MESSAGES = (
    "cortado-rta: BUG: KASAN: use-after-free in IPv4 TCP option handling",
    "cortado-rta: Call Trace: ip_options_build+0x1/0x1",
)


@register_code_rta(
    id="7c8ea878-ef4d-485b-8a14-3208e29512f5",
    name="linux_kernel_ipv4_tcp_use_after_free_call_trace",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="b76157d9-fea4-4a31-a1eb-e448c5516c8d",
            name="Linux Kernel IPv4 TCP Use-After-Free Call Trace",
        )
    ],
    techniques=["T1190", "T1210"],
)
def main() -> None:
    """Emit synthetic kernel messages that satisfy the rule correlation."""
    if os.geteuid() != 0:
        log.error("Writing synthetic kernel messages to %s requires root", KMSG_PATH)
        return

    try:
        kmsg_fd = os.open(KMSG_PATH, os.O_WRONLY)
        try:
            for message in KERNEL_MESSAGES:
                _ = os.write(kmsg_fd, f"<4>{message}\n".encode())
                log.info("Wrote synthetic kernel message: %s", message)
        finally:
            os.close(kmsg_fd)
    except OSError as error:
        log.error("Unable to write synthetic kernel messages to %s: %s", KMSG_PATH, error)
        return

    log.info("Synthetic kernel use-after-free and IPv4/TCP call-trace messages emitted")
