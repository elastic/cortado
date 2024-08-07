# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
from . import _common, RuleMetadata, register_code_rta, OSType
import pathlib


@register_code_rta(
    id="884ae75b-d9ed-448c-9267-fb470fffb249",
    name="persistence_shell_via_web_server",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="753f83ff-437b-4952-8612-07e3c1327daf", name="Potential Shell via Web Server")],
    siem_rules=[],
    techniques=["T1505", "T1505.003"],
)
def main():
    masquerade = "/tmp/httpd"
    masquerade2 = "/tmp/bash"
    # used only for linux at 2 places to enumerate xargs as parent process.
    working_dir = "/tmp/fake_folder/httpd"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = _common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    _common.copy_file(source, masquerade)
    _common.copy_file(source, masquerade2)
    # In linux the working directory is being projected as parent process.
    # Hence, to simulate the parent process without many changes to execute logic
    # a fake folder structure is created for execution.
    # The execution working directory is changed to the fake folder, to simulate as xargs parent process in Linux.
    pathlib.Path(working_dir).mkdir(parents=True, exist_ok=True)
    os.chdir(working_dir)

    # Execute command
    _common.log("Launching fake commands for potential shell via webserver")
    command = f"{masquerade2} pwd"
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)
    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    _common.remove_directory(working_dir)
