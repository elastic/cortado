# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import register_code_rta, OSType, RuleMetadata


@register_code_rta(
    id="9bf3622b-dd76-4156-a89c-6845dca46b1f",
    name="clr_logs_creation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(
            id="5a898048-d98c-44c6-b7ba-f63a31eb3571", name="Managed .NET Code Execution via Windows Script Interpreter"
        ),
    ],
    siem_rules=[],
    techniques=["T1220", "T1218", "T1055", "T1059"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    msxsl = "C:\\Users\\Public\\msxsl.exe"
    fake_clr_path = "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs"
    fake_clr_logs = fake_clr_path + "\\msxsl.exe.log"
    _common.copy_file(EXE_FILE, msxsl)

    Path(fake_clr_path).mkdir(parents=True, exist_ok=True)
    _common.log("Creating a fake clr log file")
    _common.execute([msxsl, "-c", f"echo RTA > {fake_clr_logs}"], timeout=10)
    _common.remove_files(msxsl, fake_clr_logs)
