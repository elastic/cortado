# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os
import pathlib

from . import _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c69a06f3-3873-4d5d-8584-035e0921b4a8",
    name="builtin_cmd_file_delete",
    platforms=["macos", "linux"],
    endpoint_rules=[
        RuleMetadata(
            id="15019d7c-42e6-4cf7-88b0-0c3a6963e6f5", name="Suspicious Recursive File Deletion via Built-In Utilities"
        )
    ],
    siem_rules=[],
    techniques=["T1565", "T1485"],
)
def main():
    masquerade = "/tmp/xargs"
    masquerade2 = "/tmp/rm"
    # used only for linux at 2 places to enumerate xargs as parent process.
    working_dir = "/tmp/fake_folder/xargs"
    if _common.CURRENT_OS == "linux":
        # Using the Linux binary that simulates parent-> child process in Linux
        source = _common.get_resource_path("bin/linux_ditto_and_spawn_parent_child")
        _common.copy_file(source, masquerade)
        _common.copy_file(source, masquerade2)
        # As opposed to macos, where the masquerade is being projected as parent process,
        # in linux the working directory is being projected as parent process.
        # Hence, to simulate the parent process without many changes to execute logic
        # a fake folder structure is created for execution.
        # The execution working directory is changed to the fake folder, to simulate as xargs parent process in Linux.
        pathlib.Path(working_dir).mkdir(parents=True, exist_ok=True)
        os.chdir(working_dir)
    else:
        _common.create_macos_masquerade(masquerade)
        _common.create_macos_masquerade(masquerade2)

    # Execute command
    log.info("Launching fake builtin commands to recursively delete")
    command = f"{masquerade2} -rf arg1 arg2 arg3 arg4 arg5 arg6 arg7 arg8 arg9 arg10 /home/test"
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10, kill=True, shell=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    if _common.CURRENT_OS == "linux":
        _common.remove_directory(working_dir)
