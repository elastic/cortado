# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a330f58c-c808-45d9-b8be-9c2054285c08",
    name="file_create_lsass_dump",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="f2f46686-6f3c-4724-bd7d-24e31c70f98f", name="LSASS Memory Dump Creation")],
    techniques=["T1003", "T1003.001"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    fake_dmp = "C:\\Users\\Public\\lsass_test.dmp"

    # Execute command
    _ = _common.execute_command([powershell, "/c", f"echo AAAAAAAAAA | Out-File {fake_dmp}"], timeout_secs=5)
    _common.remove_file(fake_dmp)
