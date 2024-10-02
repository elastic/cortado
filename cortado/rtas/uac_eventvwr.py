# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7396debc-65ce-488f-845e-f92e68aceeb1",
    name="uac_eventvwr",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="ab29a79a-b3c2-4ae4-9670-70dd0ea68a4a", name="UAC Bypass via Event Viewer"),
    ],
    techniques=["T1548", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    eventvwr = "C:\\Users\\Public\\eventvwr.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    _common.copy_file(EXE_FILE, eventvwr)

    _ = _common.execute_command([eventvwr, "/c", powershell], timeout_secs=2)
    _common.remove_files([eventvwr])
