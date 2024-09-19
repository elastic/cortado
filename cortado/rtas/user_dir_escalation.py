# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: SYSTEM Escalation from User Directory
# RTA: user_dir_escalation.py
# ATT&CK: T1044
# Description: Spawns mock malware written to a regular user directory and executes as System.

import logging
import os
from pathlib import Path

from . import OSType, _common, register_code_rta, _const

log = logging.getLogger(__name__)


@register_code_rta(
    id="dc734786-66bd-4be6-bd06-eb41fa7b6745",
    name="user_dir_escalation",
    platforms=[OSType.WINDOWS],
    ancillary_files=[_const.PS_EXEC_EXE],
)
def main() -> None:
    # make sure path is absolute for psexec
    if not _common.elevate_to_system():
        raise _common.ExecutionError("Can't elevate to system")

    log.info("Run a user-writeable file as system")
    source_path = _common.get_resource_path("bin/myapp.exe")

    target_directory = "c:\\users\\fake_user_rta-%d" % os.getpid()
    if not Path(target_directory).is_dir():
        Path(target_directory).mkdir(parents=True)

    target_path = Path(target_directory) / "user_file.exe"
    _common.copy_file(source_path, target_path)
    _ = _common.execute_command([str(target_path)])

    _common.remove_directory(target_directory)
