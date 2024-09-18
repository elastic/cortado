# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="19b6d1cd-6342-42f0-9f1d-20185f5b3d95",
    name="exec_cmd_hidden_share",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="fa01341d-6662-426b-9d0c-6d81e33c8a9d", name="Remote File Copy to a Hidden Share")],
    techniques=["T1021", "T1021.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    xcopy = "C:\\Users\\Public\\xcopy.exe"
    _common.copy_file(EXE_FILE, xcopy)

    # Execute command
    _ = _common.execute_command([xcopy, "/c", "echo", "mv", "A$"], timeout_secs=10)
    _common.remove_file(xcopy)
