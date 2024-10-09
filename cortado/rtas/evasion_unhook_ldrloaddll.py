# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7fcf2f31-b510-45f8-9de4-7dc8f5ecb68b",
    name="evasion_unhook_ldrloaddll",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="d7bc9652-fe82-4fb3-8a48-4a9289c840f8", name="Potential NTDLL Memory Unhooking"),
        RuleMetadata(id="2c4f5a78-a64f-4fcf-ac52-bf91fd9b82c8", name="Suspicious Image Load via LdrLoadDLL"),
        RuleMetadata(id="703343f1-095a-4a5a-9bf4-5338db06ecb8", name="Process Creation from Modified NTDLL"),
    ],
    techniques=["T1055"],
)

# testing PE that will first unhook ntdll txt section and load ws2_32.dll, create notepad.exe from unhooked ntdll then load psapi.dll via LdrLoadDll
# source code -https://gist.github.com/Samirbous/cee44dbd0254c28d4f57709d5c723aee
def main():
    bin_exe = _common.get_resource_path("bin/rta_unhook_ldrload.exe")

    if bin_exe.is_file():
        log.info(f"File {bin_exe} will be executed")
        _ = _common.execute_command(str(bin_exe), shell=True)
        # cleanup
        _ = _common.execute_command(["taskkill", "/f", "/im", "notepad.exe"])
