# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="75167553-4886-44ba-b5d6-b4c341b33709",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Suspicious Network Connection from Microsoft Equation Editor",
            "rule_id": "365571bb-2b93-4ae8-8c39-0558f8a6c4cc",
        }
    ],
    siem_rules=[],
    techniques=["T1203", "T1566"],
)

EXE_FILE = _common.get_path("bin", "regsvr32.exe")



def main():
    eqnedt32 = "C:\\Users\\Public\\eqnedt32.exe"

    _common.copy_file(EXE_FILE, eqnedt32)
    _common.log("Making connection using fake eqnedt32.exe")
    _common.execute([eqnedt32, "-Embedding"], timeout=10, kill=True)


