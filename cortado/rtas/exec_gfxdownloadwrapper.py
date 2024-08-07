# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="e7f3a729-e5ee-462b-ba1c-dd778468d24d",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="aafe3c78-15d9-4853-a602-663b8fada5b5", name="Potential Evasion via Intel GfxDownloadWrapper")
    ],
    siem_rules=[],
    techniques=["T1218", "T1105"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    gfx = "C:\\Users\\Public\\GfxDownloadWrapper.exe"
    _common.copy_file(EXE_FILE, gfx)

    _common.execute([gfx, "/c", "echo", "run", "0", "http"], timeout=5, kill=True)
    _common.remove_files(gfx)
