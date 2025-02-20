# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Run Process from the Recycle Bin
# RTA: recycle_bin_process.py
# ATT&CK: T1158
# Description: Executes mock malware from the "C:\Recycler\" and "C:\$RECYCLE.BIN\" subdirectories.

import logging
import time
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


RECYCLE_PATHS = ["C:\\$Recycle.Bin", "C:\\Recycler"]
TARGET_APP_EXE = "bin/myapp.exe"


@register_code_rta(
    id="790cbe6f-ee44-4654-9998-039236dbe0d8",
    name="recycle_bin_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="cff92c41-2225-4763-b4ce-6f71e5bda5e6", name="Execution from Unusual Directory - Command Line")
    ],
    techniques=["T1036", "T1059"],
    ancillary_files=[TARGET_APP_EXE],
)
def main():
    log.info("Execute files from the Recycle Bin")
    target_dir = None
    for recycle_path in RECYCLE_PATHS:
        if Path(recycle_path).exists():
            target_dir = _common.find_writeable_directory(recycle_path)
            if target_dir:
                break
    else:
        log.info("Could not find a writeable directory in the recycle bin")
        raise _common.ExecutionError("Could not find a writeable directory in the recycle bin")

    if not target_dir:
        raise _common.ExecutionError("No writable directories in `RECYCLE_PATHS`")

    log.info("Running commands from recycle bin in %s" % target_dir)
    target_path = Path(target_dir) / "recycled_process.exe"

    target_app_exe = _common.get_resource_path(TARGET_APP_EXE)
    _common.copy_file(target_app_exe, target_path)
    _ = _common.execute_command(str(target_path), shell=True)

    time.sleep(0.5)
    _common.remove_file(target_path)

    cmd_path = _common.get_cmd_path()
    _common.copy_file(cmd_path, target_path)
    _ = _common.execute_command(
        [target_path, "/c", "echo hello world"],
    )
    time.sleep(0.5)
    _common.remove_file(target_path)
