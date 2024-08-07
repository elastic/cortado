# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common

import subprocess


@register_code_rta(
    id="5132ee2a-25ae-4c2d-abe0-5bc3a9fbcab2",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {"rule_name": "Linux Background Process Execution via Shell", "rule_id": "21692d53-d4a5-462c-9ee6-2d8788411996"}
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
    _common.execute(["chmod", "+x", parent_process])

    # Execute the fake parent process script
    _common.log("Executing the fake parent process script")
    subprocess.Popen([parent_process])

    _common.log("RTA execution completed.")

    # Cleanup
    _common.remove_file(parent_process)


if __name__ == "__main__":
    exit(main())
