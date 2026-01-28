# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Internal Defacement Simulation
# RTA: defacement_internal.py
# ATT&CK: T1491.001
# Description: Simulates internal defacement techniques used by ransomware and
#              destructive malware, including wallpaper changes and login message
#              modifications. All changes are temporary and reversible.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    name="defacement_internal",
    platforms=[OSType.WINDOWS, OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="b1b2c3d4-e5f6-7890-abcd-ef1234567891",
            name="Potential Internal Defacement via Registry Modification",
        ),
        RuleMetadata(
            id="c1b2c3d4-e5f6-7890-abcd-ef1234567892",
            name="Suspicious Wallpaper Change via Command Line",
        ),
        RuleMetadata(
            id="b2b3c4d5-e6f7-8901-bcde-f12345678902",
            name="Potential Internal Defacement via MOTD Modification",
        ),
    ],
    siem_rules=[
        RuleMetadata(
            id="d1b2c3d4-e5f6-7890-abcd-ef1234567893",
            name="Potential Ransomware Defacement Activity",
        ),
        RuleMetadata(
            id="c2b3c4d5-e6f7-8901-bcde-f12345678903",
            name="Linux Internal Defacement Activity",
        ),
    ],
    techniques=["T1491", "T1491.001", "T1112"],
)
def main():
    """
    Simulates internal defacement techniques commonly used by ransomware.

    This RTA demonstrates defacement patterns without causing permanent damage.
    Detects the current OS and runs the appropriate simulation.
    """
    current_os = _common.get_current_os()

    if current_os == OSType.WINDOWS:
        _run_windows()
    elif current_os == OSType.LINUX:
        _run_linux()
    else:
        log.warning(f"Unsupported OS: {current_os}")


def _run_windows():
    """Windows-specific defacement simulation."""
    log.info("Simulating Windows internal defacement techniques")
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Simulate wallpaper change via registry (common ransomware technique)
    log.info("Simulating wallpaper modification via registry")
    wallpaper_cmd = (
        "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' "
        "-Name Wallpaper -Value 'C:\\ransom_note.bmp'"
    )
    _ = _common.execute_command(
        [powershell, "-Command", "echo", f"'{wallpaper_cmd}'"],
        timeout_secs=10,
    )

    # Simulate legal notice modification (login banner defacement)
    log.info("Simulating login banner modification")
    legal_notice_cmd = (
        "Set-ItemProperty -Path "
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name legalnoticecaption -Value 'YOUR FILES HAVE BEEN ENCRYPTED'"
    )
    _ = _common.execute_command(
        [powershell, "-Command", "echo", f"'{legal_notice_cmd}'"],
        timeout_secs=10,
    )

    # Create a temporary defacement marker file (ransomware often drops README files)
    log.info("Creating temporary defacement marker file")
    defacement_file = Path("C:\\Users\\Public\\README_ENCRYPTED.txt")
    defacement_content = (
        "This is a simulated ransomware note for detection testing.\n"
        "This file was created by an Elastic RTA and is safe to delete.\n"
        "MITRE ATT&CK: T1491.001 - Defacement: Internal Defacement\n"
    )
    _common.create_file_with_data(str(defacement_file), defacement_content)

    # Simulate SystemParametersInfo call for wallpaper (via PowerShell echo)
    log.info("Simulating SystemParametersInfo wallpaper call")
    spi_cmd = (
        "[DllImport('user32.dll')] static extern bool SystemParametersInfo(uint action, "
        "uint param, string vparam, uint init); SystemParametersInfo(0x0014, 0, 'ransom.bmp', 0x01)"
    )
    _ = _common.execute_command(
        [powershell, "-Command", "echo", f"'{spi_cmd}'"],
        timeout_secs=10,
    )

    # Simulate HTML file modification (intranet defacement)
    log.info("Simulating intranet page defacement")
    html_defacement = Path("C:\\Users\\Public\\defaced_page.html")
    html_content = (
        "<html><body><h1>HACKED BY RTA SIMULATION</h1>"
        "<p>This is a test file for defacement detection.</p></body></html>"
    )
    _common.create_file_with_data(str(html_defacement), html_content)

    # Cleanup created files
    log.info("Cleaning up defacement simulation files")
    _common.remove_file(str(defacement_file))
    _common.remove_file(str(html_defacement))

    log.info("Windows internal defacement simulation completed")


def _run_linux():
    """Linux-specific defacement simulation."""
    log.info("Simulating Linux internal defacement techniques")

    # Create masquerade binary for command execution
    masquerade = "/tmp/bash"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Simulate MOTD modification (common Linux defacement target)
    log.info("Simulating MOTD modification")
    _ = _common.execute_command(
        [masquerade, "echo", "'HACKED' > /etc/motd"],
        timeout_secs=10,
    )

    # Simulate web root defacement
    log.info("Simulating web root defacement")
    _ = _common.execute_command(
        [masquerade, "echo", "'<h1>DEFACED</h1>' > /var/www/html/index.html"],
        timeout_secs=10,
    )

    # Simulate SSH banner modification
    log.info("Simulating SSH banner modification")
    _ = _common.execute_command(
        [masquerade, "echo", "'SYSTEM COMPROMISED' > /etc/ssh/banner"],
        timeout_secs=10,
    )

    # Simulate issue file modification (pre-login message)
    log.info("Simulating /etc/issue modification")
    _ = _common.execute_command(
        [masquerade, "echo", "'YOUR SYSTEM HAS BEEN HACKED' > /etc/issue"],
        timeout_secs=10,
    )

    # Create temporary defacement marker
    log.info("Creating temporary defacement marker")
    defacement_file = "/tmp/RANSOM_NOTE.txt"
    defacement_content = (
        "This is a simulated ransomware note for detection testing.\n"
        "MITRE ATT&CK: T1491.001 - Defacement: Internal Defacement\n"
    )
    _common.create_file_with_data(defacement_file, defacement_content)

    # Cleanup
    log.info("Cleaning up defacement simulation files")
    _common.remove_file(defacement_file)
    _common.remove_file(masquerade)

    log.info("Linux internal defacement simulation completed")
