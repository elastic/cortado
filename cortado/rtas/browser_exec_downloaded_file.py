# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common

import os


@register_code_rta(
    id="3f60cbfd-9e9b-47e4-a585-2a9d1075a3b9",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': '196f4c30-a8c5-40a5-80e3-a50c6714632f',
        'rule_name': 'Execution of File Downloaded via Internet Browser'
    }],
    siem_rules=[],
    techniques=[""],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    user = os.getenv("USERPROFILE")
    posh = f"{user}\\Downloads\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    _common.log("Executing executable from Downloads folder")
    _common.execute([posh], timeout=5, kill=True)
    _common.remove_file(posh)


