# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4aa10c2d-3839-4ed3-8ca6-a88fdd32bdef",
    name="file_create_smss_exec",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="e94262f2-c1e9-4d3f-a907-aeab16712e1a",
            name="Unusual Executable File Creation by a System Critical Process",
        )
    ],
    techniques=["T1211"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    smss = "C:\\Users\\Public\\smss.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"
    _common.copy_file(EXE_FILE, smss)

    # Execute command
    _ = _common.execute_command([smss, "/c", f"echo AAAAAAAAAA | Out-File {fake_exe}"], timeout_secs=10)
    _common.remove_files([fake_exe, smss])
