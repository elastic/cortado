# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import subprocess
import logging
import time
from pathlib import Path

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="6a3d9ca4-d010-42c7-b75a-7dc8ce347e59",
    name="linux_motd_netcon",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="a18e57c9-5627-4535-b994-64febc67c1e8",
            name="Message of the Day Execution Followed by Network Connection",
        ),
    ],
    techniques=["T1037", "T1059", "T1071"],
)
def main() -> None:
    parent_process_path = "/etc/update-motd.d/rta"
    child_script_path = "/tmp/child.sh"
    network_command = "exec 3<>/dev/tcp/8.8.8.8/53"

    # Create the fake parent process script
    with Path(parent_process_path).open("w", encoding="utf-8") as parent_script:
        _ = parent_script.write("#!/bin/bash\n")
        _ = parent_script.write(f"{child_script_path}\n")

    # Create the child script that will make the network connection
    with Path(child_script_path).open("w", encoding="utf-8") as child_script:
        _ = child_script.write("#!/bin/bash\n")
        _ = child_script.write(f"{network_command}\n")

    # Make the scripts executable
    _ = _common.execute_command(["chmod", "+x", parent_process_path])
    _ = _common.execute_command(["chmod", "+x", child_script_path])

    # Execute the parent process script
    log.info("Executing the fake parent process script")
    _ = subprocess.Popen([parent_process_path])  # noqa: S603

    # Allow some time for the network connection to be attempted
    time.sleep(5)
    log.info("RTA execution completed.")

    # Cleanup
    _common.remove_file(parent_process_path)
    _common.remove_file(child_script_path)
