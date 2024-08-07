# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="5cf6e510-b0c3-41f2-93d4-1210d68802c5",
    name="exec_nodejs",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="a34c5dc0-a353-4c1f-9b08-6f0aca4f1f45", name="Suspicious JavaScript Execution via Node.js")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    node = "C:\\Users\\Public\\node.exe"
    _common.copy_file(EXE_FILE, node)

    _common.execute([node, "echo", "-e"], timeout=10)
    _common.remove_files(node)
