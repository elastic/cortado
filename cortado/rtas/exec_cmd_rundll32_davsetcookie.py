# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="3a84dc01-0202-4aee-8cd1-5fdefead9f4f",
    name="exec_cmd_rundll32_davsetcookie",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="4682fd2c-cfae-47ed-a543-9bed37657aa6", name="Potential Local NTLM Relay via HTTP")],
    techniques=["T1212"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    _common.copy_file(EXE_FILE, rundll32)

    # Execute command
    _ = _common.execute_command(
        [rundll32, "/c", "echo", "C:\\Windows\\System32\\davclnt.dll,DavSetCookie", "https*/print/pipe/"],
        timeout_secs=10,
    )
    _common.remove_file(rundll32)
