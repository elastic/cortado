# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5cf6e510-b0c3-41f2-93d4-1210d68802c5",
    name="exec_nodejs",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="a34c5dc0-a353-4c1f-9b08-6f0aca4f1f45", name="Suspicious JavaScript Execution via Node.js")
    ],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    node = "C:\\Users\\Public\\node.exe"
    _common.copy_file(EXE_FILE, node)

    _ = _common.execute_command([node, "echo", "-e"], timeout_secs=10)
    _common.remove_files([node])
