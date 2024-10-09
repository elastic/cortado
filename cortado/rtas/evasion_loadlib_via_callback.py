# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ae4b2807-3a16-485e-bb69-5d36bbe9b7d1",
    name="evasion_loadlib_via_callback",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="fae9f554-d3bc-4d48-8863-54d0dd68db54", name="Library Loaded via a CallBack Function")
    ],
    techniques=["T1574"],
)

# testing PE that will load ws2_32 and dnsapi.dll via a Callback function using RtlQueueWorkItem and RtlRegisterWait
# source code - https://gist.github.com/joe-desimone/0b2bb00eca4c522ba0bd5541a6f3528b
def main():
    bin_exe = _common.get_resource_path("bin/LoadLib-Callback64.exe")

    if bin_exe.is_file():
        log.info(f"File {bin_exe} will be executed")
        _ = _common.execute_command(str(bin_exe), shell=True)
        # cleanup
        _ = _common.execute_command(["taskkill", "/f", "/im", "LoadLib-Callback64.exe"])
        log.info("RTA Done!")
