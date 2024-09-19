# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ad0986cb-b5ef-41ad-9b40-8d708dc28844",
    name="exec_vsls_agent",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="a5416b1f-fc3f-4162-936d-34086689c3b0", name="DLL Execution via Visual Studio Live Share")
    ],
    siem_rules=[],
    techniques=["T1218"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    vslsagent = "C:\\Users\\Public\\vsls-agent.exe"
    _common.copy_file(EXE_FILE, vslsagent)

    _ = _common.execute_command([vslsagent, "/c", "echo", "--agentExtensionPath"], timeout_secs=5)
    _common.remove_files([vslsagent])
