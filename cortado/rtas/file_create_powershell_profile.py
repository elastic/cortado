# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path


@register_code_rta(
    id="1bc32d6d-c5c9-43c6-bada-6d26469b5dac",
    name="file_create_powershell_profile",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="5cf6397e-eb91-4f31-8951-9f0eaa755a31", name="Persistence via PowerShell profile")],
    techniques=["T1546", "T1546.013"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    path = "C:\\Users\\Public\\Documents\\WindowsPowerShell"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\profile.ps1"
    _common.copy_file(EXE_FILE, file)

    _common.remove_files(file)
