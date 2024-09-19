# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a840e9b2-5aac-41a1-8c79-03ff624eb77b",
    name="suspicious_child_services",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="0022d47d-39c7-4f69-a232-4fe9dc7a3acd", name="System Shells via Services")],
    techniques=["T1543", "T1543.003"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    services = "C:\\Users\\Public\\services.exe"
    pwsh = "C:\\Users\\Public\\pwsh.exe"
    _common.copy_file(EXE_FILE, pwsh)
    _common.copy_file(EXE_FILE, services)

    _ = _common.execute_command([services, "/c", pwsh], timeout_secs=5)
    _common.remove_files([pwsh, services])
