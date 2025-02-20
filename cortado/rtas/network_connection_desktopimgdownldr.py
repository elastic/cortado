# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="127f1e70-a491-4da4-a24f-ac6bf6e5b756",
    name="network_connection_desktopimgdownldr",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="15c0b7a7-9c34-4869-b25b-fa6518414899", name="Remote File Download via Desktopimgdownldr Utility"
        )
    ],
    techniques=["T1105"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    desktopimgdownldr = "C:\\Users\\Public\\desktopimgdownldr.exe"
    _common.copy_file(EXE_FILE, desktopimgdownldr)

    # Execute command
    _ = _common.execute_command([desktopimgdownldr, "/c", "echo", "/lockscreenurl:http"], timeout_secs=10)
    _common.remove_file(desktopimgdownldr)
