# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="bc837b89-713a-4d21-a086-8649e8411f11",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="9a5b4e31-6cde-4295-9ff7-6be1b8567e1b", name="Suspicious Explorer Child Process")],
    techniques=["T1566", "T1566.001", "T1566.002"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    explorer = "C:\\Users\\Public\\explorer.exe"
    _common.copy_file(EXE_FILE, explorer)

    _common.execute([explorer, "-c", "echo", "-Embedding", ";powershell"], timeout=5, kill=True)
    _common.remove_file(explorer)
