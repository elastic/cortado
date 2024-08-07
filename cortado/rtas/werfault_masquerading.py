# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="41c82553-01c2-41d6-a15d-3499fa99b4c0",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="3d16f5f9-da4c-4b15-a501-505761b75ca6", name="Windows Error Manager/Reporting Masquerading")
    ],
    siem_rules=[],
    techniques=["T1055", "T1036"],
)

EXE_FILE = _common.get_path("bin", "regsvr32.exe")



def main():
    werfault = "C:\\Users\\Public\\werfault.exe"

    _common.copy_file(EXE_FILE, werfault)
    _common.log("Making connection using fake werfault.exe")
    _common.execute([werfault], timeout=10, kill=True)
    _common.remove_file(werfault)


