# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import subprocess
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="65978ab7-37d2-4542-8e03-50b3d408ff42",
    name="linux_execution_linux_powershell_outbound_network_connection",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="1471cf36-7e5c-47cc-bf39-2234df0e676a", name="Linux Powershell Egress Network Connection"),
    ],
    techniques=["T1203"],
)
def main() -> None:
    parent_process_path = "/tmp/pwsh"
    child_script_path = "/tmp/sh"
    network_command = "exec 3<>/dev/tcp/8.8.8.8/53"

    # Create the fake parent process script
    with open(parent_process_path, "w") as parent_script:  # noqa: PTH123
        _ = parent_script.write("#!/bin/bash\n")
        _ = parent_script.write(f"{child_script_path}\n")

    # Create the child script that will make the network connection
    with open(child_script_path, "w") as child_script:  # noqa: PTH123
        _ = child_script.write("#!/bin/bash\n")
        _ = child_script.write(f"{network_command}\n")

    # Make the scripts executable
    _ = _common.execute_command(["chmod", "+x", parent_process_path])
    _ = _common.execute_command(["chmod", "+x", child_script_path])

    # Execute the parent process script
    log.info("Executing the fake parent process script")
    _ = subprocess.Popen([parent_process_path])

    # Allow some time for the network connection to be attempted
    time.sleep(5)
    log.info("RTA execution completed.")

    # Cleanup
    _common.remove_file(parent_process_path)
    _common.remove_file(child_script_path)
