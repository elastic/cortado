# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a296162b-65c1-4fbe-ae34-67f606de408e",
    name="exec_cmd_pwd_appcmd",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="0564fb9d-90b9-4234-a411-82a546dc1343", name="Microsoft IIS Service Account Password Dumped")
    ],
    techniques=["T1003"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    appcmd = "C:\\Users\\Public\\appcmd.exe"
    _common.copy_file(EXE_FILE, appcmd)

    # Execute command
    _ = _common.execute_command([appcmd, "/c", "echo", "/list", "/text&password"], timeout_secs=10)
    _common.remove_file(appcmd)
