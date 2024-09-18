# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0da48a27-4a5e-4974-ba6a-63cce8f602df",
    name="file_creation_teamviewer",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="b25a7df2-120a-4db2-bd3f-3e4b86b24bee", name="Remote File Copy via TeamViewer")],
    techniques=["T1105", "T1219"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    teamviewer = "C:\\Users\\Public\\teamviewer.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"
    _common.copy_file(EXE_FILE, teamviewer)

    # Execute command
    _ = _common.execute_command([teamviewer, "/c", f"echo AAAAAAAAAA | Out-File {fake_exe}"], timeout_secs=10)
    _common.remove_files([fake_exe, teamviewer])
