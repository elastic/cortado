# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="61abdbb3-bcab-4c57-8b5d-2a5c9226e580",
    name="msoffice_reg_mod",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="926b6cd1-c0c7-46d4-82d6-9deb6ae431d6", name="Registry Modification via Microsoft Office")
    ],
    techniques=["T1547", "T1112", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    winword = "C:\\Users\\Public\\winword.exe"
    _common.copy_file(EXE_FILE, winword)

    cmd = (
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Test -PropertyType String -value Testing"
    )
    rem_cmd = "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Test"

    # Execute command
    log.info("Fake ms word reg mod...")
    _ = _common.execute_command([winword, "/c", cmd], timeout_secs=10)
    _ = _common.execute_command([winword, "/c", rem_cmd], timeout_secs=10)
    _common.remove_file(winword)
