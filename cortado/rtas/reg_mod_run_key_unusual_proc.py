# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a3461218-f6c2-4178-ad85-f25b8df2d2e1",
    name="reg_mod_run_key_unusual_proc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b2fcbb09-d9bd-4f6c-a08e-247548b4edcd", name="Registry Run Key Modified by Unusual Process"),
        RuleMetadata(
            id="727db78e-e1dd-4bc0-89b0-885cd99e069e", name="Suspicious String Value Written to Registry Run Key"
        ),
    ],
    techniques=["T1547"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    posh = "C:\\Windows\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    cmd = (
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Test -PropertyType String -value rundll32"
    )
    rem_cmd = "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Test"

    # Execute command
    log.info("Fake ms word reg mod...")
    _ = _common.execute_command([posh, "/c", cmd], timeout_secs=10)
    _ = _common.execute_command([posh, "/c", rem_cmd], timeout_secs=10)
    _common.remove_file(posh)
