# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="4fd98e1e-6a58-4684-b565-aa7a09b29d6b",
    name="msoffice_onenote_susp_child",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="28297d1e-c2a9-442c-9e48-98fe8ce36fab", name="Suspicious Microsoft OneNote Child Process")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    onenote = "C:\\Users\\Public\\onenote.exe"
    _common.copy_file(EXE_FILE, onenote)

    _common.execute([onenote, "/c", "powershell"], timeout=1, kill=True)
    _common.remove_file(onenote)
