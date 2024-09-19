# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8c22e0f5-7c5b-46eb-b04c-28f32ac5b564",
    name="exec_forfiles",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="78afa378-d1c4-4b83-a261-ce1c90f1cbf9", name="Indirect Command Execution via ForFiles")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    forfiles = "C:\\Users\\Public\\forfiles.exe"
    _common.copy_file(EXE_FILE, forfiles)

    # Execute command
    _ = _common.execute_command([forfiles, "/c", "/m", "/p"], timeout_secs=10)

    _common.remove_file(forfiles)
