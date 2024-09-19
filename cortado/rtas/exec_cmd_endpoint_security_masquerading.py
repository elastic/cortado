# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="be77efd7-8f6a-4033-92b9-f47addb60866",
    name="exec_cmd_endpoint_security_masquerading",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="b41a13c6-ba45-4bab-a534-df53d0cfed6a", name="Suspicious Endpoint Security Parent Process")
    ],
    techniques=["T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    esensor = "C:\\Users\\Public\\esensor.exe"
    _common.copy_file(EXE_FILE, esensor)

    # Execute command
    _ = _common.execute_command([esensor], timeout_secs=2)
    _common.remove_files([esensor])
