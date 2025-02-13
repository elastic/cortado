# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import subprocess

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="075664b1-83db-4cb1-9280-e18309e187bc",
    name="linux_shell_exec_of_non_executable_file",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="4c61fca2-6f77-474d-a537-2d7fd9ec75e0", name="Shell Execution of Non-Executable File")
    ],
    techniques=["T1036", "T1059"],
)
def main():
    shell_command = "/bin/bash"
    file_pattern = "/bin/bash /tmp/evil.log"

    # Create a dummy file
    dummy_file = "/tmp/evil"
    with open(dummy_file, "w") as script:
        _ = script.write("This is a dummy log file.\n")

    # Execute the shell command with the file pattern command as an argument
    log.info("Launching shell command to simulate non-executable file execution")
    _ = subprocess.Popen([shell_command, "-c", file_pattern])

    log.info("RTA execution completed.")

    # Cleanup
    _common.remove_file(dummy_file)
