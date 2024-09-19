# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="3f60cbfd-9e9b-47e4-a585-2a9d1075a3b9",
    name="browser_exec_downloaded_file",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="196f4c30-a8c5-40a5-80e3-a50c6714632f", name="Execution of File Downloaded via Internet Browser"
        )
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    user = os.getenv("USERPROFILE")
    posh = f"{user}\\Downloads\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    log.info("Executing executable from Downloads folder")
    _ = _common.execute_command([posh], timeout_secs=5)
    _common.remove_file(posh)
