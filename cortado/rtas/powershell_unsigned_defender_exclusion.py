# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1ccbd3c6-69c8-4476-b5e5-da3d167a09f1",
    name="powershell_unsigned_defender_exclusion",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="2ad8b514-baf0-4e29-a712-d6734868aa57",
            name="Suspicious Windows Defender Exclusions Added via PowerShell",
        )
    ],
    techniques=["T1562", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    cmd = "powershell -c Add-MpPreference -ExclusionPath"
    # Execute command
    _ = _common.execute_command([posh, "/c", cmd], timeout_secs=10)
    _common.remove_file(posh)
