# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5e911636-6f68-40d3-b1ef-7a951a397cc9",
    name="exec_explorer_trampoline",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="5e8498bb-8cc0-412f-9017-793d94ab76a5",
            name="Execution of Commonly Abused Utilities via Explorer Trampoline",
        )
    ],
    techniques=["T1218", "T1566", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    explorer = "C:\\Users\\Public\\explorer.exe"
    _common.copy_file(EXE_FILE, explorer)

    _ = _common.execute_command(
        [
            explorer,
            "-c",
            "echo",
            "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}",
            ";mshta",
        ],
        timeout_secs=10,
    )
    _common.remove_files([explorer])
