# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="245fcf03-6df8-4731-af94-f2ba4ed60670",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Unusual File Written or Modified in Startup Folder",
            "rule_id": "30a90136-7831-41c3-a2aa-1a303c1186ac",
        },
        RuleMetadata(id="0b33141a-3f73-4414-ba90-d8410e6ab176", name="Network Connection via Startup Item"),
    ],
    siem_rules=[],
    techniques=["T1547", "T1218", "T1036", "T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    posh = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    _common.execute(
        [
            posh,
            "/c",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "445",
        ],
        timeout=10,
    )
    _common.remove_files(posh)


