# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="245fcf03-6df8-4731-af94-f2ba4ed60670",
    name="unsigned_startup_item_netconn",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="30a90136-7831-41c3-a2aa-1a303c1186ac", name="Unusual File Written or Modified in Startup Folder"
        ),
        RuleMetadata(id="0b33141a-3f73-4414-ba90-d8410e6ab176", name="Network Connection via Startup Item"),
    ],
    techniques=["T1547", "T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    posh = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    _ = _common.execute_command(
        [
            posh,
            "/c",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "445",
        ],
        timeout_secs=10,
    )
    _common.remove_files([posh])
