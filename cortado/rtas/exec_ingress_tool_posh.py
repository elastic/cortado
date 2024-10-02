# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0c0febf3-1ac3-4198-a31a-ec80b1f5ebbe",
    name="exec_ingress_tool_posh",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="5abd98fb-ffbe-4cd6-9592-3cda7b155ff5", name="Ingress Tool Transfer via PowerShell"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    techniques=["T1105", "T1059", "T1059.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    powershell = "C:\\Users\\Public\\powershell.exe"
    _common.copy_file(EXE_FILE, powershell)

    _ = _common.execute_command([powershell, "echo http;", powershell], timeout_secs=5)
    _common.remove_files([powershell])
