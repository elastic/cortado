# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c562a05e-0ac8-46f9-91a2-5e99c8a1117c",
    name="exec_cscript_suspicious_powershell",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="3899dd3b-f31a-4634-8467-55326cd87597", name="Suspicious PowerShell Execution via Windows Scripts"
        ),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    cscript = "C:\\Users\\Public\\cscript.exe"
    _common.copy_file(EXE_FILE, cscript)

    cmd = "powershell -c echo https://raw.githubusercontent.com/"
    # Execute command
    _ = _common.execute_command([cscript, "/c", cmd], timeout_secs=10)
    _common.remove_file(cscript)
