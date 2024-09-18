# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8fc20141-a73e-4c5e-9c9b-70acb69ab1dd",
    name="msoffice_descendant_reg_mod_persistence",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="999e7a9a-334f-4b74-834f-a652f91531f2",
            name="Registry Persistence via Microsoft Office Descendant Process",
        )
    ],
    siem_rules=[],
    techniques=["T1547", "T1112", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    winword = "C:\\Users\\Public\\winword.exe"
    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, winword)
    _common.copy_file(EXE_FILE, posh)

    cmd = (
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Test -PropertyType String -value Testing"
    )
    rem_cmd = "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Test"

    # Execute command
    log.info("Fake ms word reg mod...")
    _ = _common.execute_command([winword, "/c", posh, "/c", cmd], timeout_secs=10)
    _ = _common.execute_command([posh, "/c", rem_cmd], timeout_secs=10)
    _common.remove_file(winword)
