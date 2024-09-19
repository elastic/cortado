# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="71c81436-242d-4bc8-a195-93d1fdbc774b",
    name="exec_msdt_diagcab",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="d18721f0-dce0-4bbc-a56a-06ea511b025e", name="Suspicious Troubleshooting Pack Cabinet Execution"
        ),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    firefox = "C:\\Users\\Public\\firefox.exe"
    msdt = "C:\\Users\\Public\\msdt.exe"
    _common.copy_file(EXE_FILE, firefox)
    _common.copy_file(EXE_FILE, msdt)

    # Creating a high entropy file, and executing the rename operation
    _ = _common.execute_command(
        [firefox, "/c", "msdt.exe /c", "echo", "/cab", "C:\\Users\\Public\\"],
        timeout_secs=10,
    )
    _common.remove_files([firefox, msdt])
