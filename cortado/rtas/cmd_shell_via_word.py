# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6c399694-d21c-4a19-9e58-8fa24eb399b9",
    name="cmd_shell_via_word",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="2a396a3c-b343-42a9-b74b-c5b9925b6ee2", name="Windows Command Shell Spawned via Microsoft Office"
        )
    ],
    siem_rules=[],
    techniques=["T1566", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed.exe")

    binary = "winword.exe"
    _common.copy_file(EXE_FILE, binary)

    # Execute command
    _ = _common.execute_command([binary, "/c", "cmd.exe /c 'echo comspec'"], timeout_secs=5)

    _common.remove_files([binary])
