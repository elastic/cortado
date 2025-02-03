# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import textwrap
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="41d3cdaf-a72e-49bb-b92f-99bfe21e0854",
name="linux_sus_netcon_file_creation",    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="08ad673a-7f99-417e-8b93-a79d4faeeed3", name="Network Connection Followed by File Creation"),
    ],
    techniques=["T1071", "T1059"],
)
def main() -> None:
    script_path = "/dev/shm/evil"
    file_path = "/dev/shm/evil.txt"

    # Create a bash script that performs network connection and file creation
    script_content = textwrap.dedent(f"""
        #!/bin/bash
        # Perform network connection using bash built-in tools
        exec 3<>/dev/tcp/8.8.8.8/53
        # Create a file
        echo "Hello, World!" > {file_path}
    """).strip()

    # Write the script content to the file
    with Path(script_path).open("w", encoding="utf-8") as script_file:
        _ = script_file.write(script_content)

    # Grant execute permissions to the script
    Path(script_path).chmod(0o755)

    # Execute the script
    log.info("Executing the bash script...")
    _ = _common.execute_command([script_path], timeout_secs=5)

    # Verify if the file was created
    if Path(file_path).exists():
        log.info("File creation successful.")

    # Clean up
    log.info("Cleaning up...")
    _common.remove_file(script_path)
    _common.remove_file(file_path)
    log.info("Cleanup successful.")
