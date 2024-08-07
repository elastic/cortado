# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="3b8454af-db6b-4d4c-92c6-89ca7b6640f1",
    name="uac_windir_masq",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="adaf95d2-28ce-4880-af16-f3041b624440", name="UAC Bypass Attempt via Windows Directory Masquerading"
        )
    ],
    siem_rules=[],
    techniques=["T1548", "T1548.002"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    proc = "C:\\Users\\Public\\proc.exe"
    _common.copy_file(EXE_FILE, proc)

    _common.execute([proc, "/c", "echo", "C:\\Windows \\System32\\a.exe"], timeout=5, kill=True)
    _common.remove_files(proc)
