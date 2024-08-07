# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType

import subprocess


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
        script.write("This is a dummy log file.\n")

    # Execute the shell command with the file pattern command as an argument
    _common.log("Launching shell command to simulate non-executable file execution")
    subprocess.Popen([shell_command, "-c", file_pattern])

    _common.log("RTA execution completed.")

    # Cleanup
    _common.remove_file(dummy_file)
