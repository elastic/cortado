# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import subprocess

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5132ee2a-25ae-4c2d-abe0-5bc3a9fbcab2",
    name="linux_sus_process_execution_and_background_via_shell",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="21692d53-d4a5-462c-9ee6-2d8788411996", name="Linux Background Process Execution via Shell")
    ],
    techniques=["T1059"],
)
def main():
    shell_command = "/bin/bash"
    shell_args = "-c '/*&'"
    parent_process = "/tmp/fake_parent.sh"

    # Create the fake parent process script
    with open(parent_process, "w") as script:
        script.write("#!/bin/sh\n")
        script.write(f"{shell_command} {shell_args}\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", parent_process])

    # Execute the fake parent process script
    log.info("Executing the fake parent process script")
    subprocess.Popen([parent_process])

    log.info("RTA execution completed.")

    # Cleanup
    _common.remove_file(parent_process)
