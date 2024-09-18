# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e0e95f35-173d-4545-a1cc-ee35ee1d89b1",
    name="uac_icmluautil",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="18a26e3e-e535-4d23-8ffa-a3cdba56d16e", name="Suspicious Parent-Child Relationship"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="13fab475-06e4-4ac9-87fc-2105c7441244", name="UAC Bypass via ICMLuaUtil Elevated COM Interface"
        ),
    ],
    siem_rules=[],
    techniques=["T1055", "T1548", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    dllhost = "C:\\Users\\Public\\dllhost.exe"
    _common.copy_file(EXE_FILE, dllhost)

    _ = _common.execute_command(
        [dllhost, "/c", "echo 3E5FC7F9-9A51-4367-9063-A120244FBEC7; powershell"],
        timeout_secs=2,
        kill=True,
    )
    _common.remove_file(dllhost)
