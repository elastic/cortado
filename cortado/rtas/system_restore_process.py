# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Process Execution in System Restore
# RTA: system_restore_process.py
# ATT&CK: T1158
# Description: Copies mock malware into the System Volume Information directory and executes.

import logging
from pathlib import Path

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


SYSTEM_RESTORE = "c:\\System Volume Information"


@register_code_rta(
    id="0fcf5aeb-cebd-466d-8a2e-ddb710ec845d",
    name="system_restore_process",
    platforms=[OSType.WINDOWS],
)
def main() -> None:
    if not _common.elevate_to_system():
        log.error("Can't get the system")
        return

    log.info("System Restore Process Evasion")
    program_path = _common.get_resource_path("bin/myapp.exe")
    log.info("Finding a writeable directory in %s" % SYSTEM_RESTORE)
    target_directory = _common.find_writeable_directory(SYSTEM_RESTORE)

    if not target_directory:
        log.warning("No writeable directories in System Restore. Exiting...")
        raise _common.ExecutionError("Can't place executable in system restore dir")

    target_path = Path(target_directory) / "restore-process.exe"
    _common.copy_file(program_path, target_path)
    _ = _common.execute_command([str(target_path)])

    log.info("Cleanup")
    _common.remove_file(target_path)
