# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Process Execution in System Restore
# RTA: system_restore_process.py
# ATT&CK: T1158
# Description: Copies mock malware into the System Volume Information directory and executes.

from pathlib import Path


@register_code_rta(
    id="0fcf5aeb-cebd-466d-8a2e-ddb710ec845d",
    platforms=[OSType.WINDOWS],
)
def main():
    status = _common.run_system()
    if status is not None:
        return status

    SYSTEM_RESTORE = "c:\\System Volume Information"

    _common.log("System Restore Process Evasion")
    program_path = _common.get_path("bin", "myapp.exe")
    _common.log("Finding a writeable directory in %s" % SYSTEM_RESTORE)
    target_directory = _common.find_writeable_directory(SYSTEM_RESTORE)

    if not target_directory:
        _common.log("No writeable directories in System Restore. Exiting...", "-")
        return _common.UNSUPPORTED_RTA

    target_path = Path(target_directory) / "restore-process.exe"
    _common.copy_file(program_path, target_path)
    _common.execute(target_path)

    _common.log("Cleanup", log_type="-")
    _common.remove_file(target_path)
