# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Run Process from the Recycle Bin
# RTA: recycle_bin_process.py
# ATT&CK: T1158
# Description: Executes mock malware from the "C:\Recycler\" and "C:\$RECYCLE.BIN\" subdirectories.

import time
from pathlib import Path



@register_code_rta(
    id="790cbe6f-ee44-4654-9998-039236dbe0d8",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_id": "cff92c41-2225-4763-b4ce-6f71e5bda5e6",
            "rule_name": "Execution from Unusual Directory - Command Line",
        }
    ],
    techniques=["T1036", "T1059"],
)


RECYCLE_PATHS = ["C:\\$Recycle.Bin", "C:\\Recycler"]
TARGET_APP = _common.get_path("bin", "myapp.exe")



@_common.dependencies(TARGET_APP, _common.CMD_PATH)
def main():
    _common.log("Execute files from the Recycle Bin")
    target_dir = None
    for recycle_path in RECYCLE_PATHS:
        if Path(recycle_path).exists():
            target_dir = _common.find_writeable_directory(recycle_path)
            if target_dir:
                break

    else:
        _common.log("Could not find a writeable directory in the recycle bin")
        exit(1)

    commands = [
        [TARGET_APP],
        [_common.CMD_PATH, "/c", "echo hello world"],
    ]

    _common.log("Running commands from recycle bin in %s" % target_dir)
    for command in commands:  # type: list[str]
        source_path = command[0]
        arguments = command[1:]

        target_path = Path(target_dir) / "recycled_process.exe"
        _common.copy_file(source_path, target_path)
        arguments.insert(0, target_path)
        _common.execute(arguments)
        time.sleep(0.5)
        _common.remove_file(target_path)


