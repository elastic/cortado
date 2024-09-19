# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9f58f9e7-a0f5-48e6-a924-d437fd626195",
    name="suspicious_child_dns",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="8c37dc0e-e3ac-4c97-8aa0-cf6a9122de45", name="Unusual Child Process of dns.exe"),
        RuleMetadata(id="c7ce36c0-32ff-4f9a-bfc2-dcb242bf99f9", name="Unusual File Modification by dns.exe"),
    ],
    techniques=["T1133"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    dns = "C:\\Users\\Public\\dns.exe"
    _common.copy_file(EXE_FILE, dns)

    _ = _common.execute_command([dns, "/c", EXE_FILE, "echo AAAAAA | Out-File a.txt"], timeout_secs=5)
    _common.remove_files([dns])
