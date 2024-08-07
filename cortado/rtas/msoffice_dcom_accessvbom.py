# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="456ec321-41c8-4a41-8f6f-40b8e3d1c295",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="6a714747-2671-4523-b233-744f119949b6", name="Suspicious MS Office Execution via DCOM")
    ],
    siem_rules=[],
    techniques=["T1112", "T1566"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    winword = "C:\\Users\\Public\\winword.exe"
    _common.copy_file(EXE_FILE, winword)

    key = "SOFTWARE\\Microsoft\\Office\\Test\\Security"
    value = "AccessVBOM"
    data = "1"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass
    _common.execute([winword, "-c", "echo", "-Embedding", ";powershell"], timeout=5, kill=True)
    _common.remove_file(winword)
