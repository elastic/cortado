# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: User Execution - Malicious File
# RTA: user_execution_malicious_file.py
# ATT&CK: T1204, T1204.002
# Description: Simulates user execution techniques where a user is tricked into
#              executing malicious files downloaded from the internet or received via email.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e1f2a3b4-c5d6-7890-ef12-3456789abcde",
    name="user_execution_malicious_file",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        # Endpoint rule: Evasion via File Name Masquerading (double extension)
        RuleMetadata(
            id="ccfca0c7-c975-4735-82bd-954ffbafd00b",
            name="Evasion via File Name Masquerading",
        ),
    ],
    siem_rules=[],
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
