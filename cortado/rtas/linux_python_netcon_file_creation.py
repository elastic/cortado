# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import socket
import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="d1ad870e-9b38-429b-bc9c-62b4b9ba2821",
name="linux_python_netcon_file_creation",    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="1a2596ff-a5e7-4562-af17-97dbaf9284d5", name="Python Network Connection Followed by File Creation"),
    ],
    techniques=["T1071", "T1059"],
)
def main() -> None:
    # Define the paths
    masquerade = "/dev/shm/python"
    file_path = "/dev/shm/file"

    # Create a fake Python executable by copying a valid executable
    with Path(masquerade).open("w", encoding="utf-8") as f:
        _ = f.write("#!/bin/bash\n")
        _ = f.write('exec python "$@"\n')

    # Grant execute permissions
    Path(masquerade).chmod(0o755)

    # Perform a network connection to 8.8.8.8
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        log.info("Network connection successful.")
    except OSError as e:
        log.info(f"Network connection failed: {e}")

    # Create a file using the Python process
    try:
        with Path(file_path).open("w", encoding="utf-8") as f:
            _ = f.write("foo")
        log.info("File creation successful.")
    except OSError as e:
        log.info(f"File creation failed: {e}")

    # Clean up
    try:
        _common.remove_file(masquerade)
        _common.remove_file(file_path)
        log.info("Cleanup successful.")
    except OSError as e:
        log.info(f"Cleanup failed: {e}")
