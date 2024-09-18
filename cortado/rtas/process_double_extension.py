# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Double Process Extension
# RTA: process_double_extension.py
# ATT&CK: T1036
# Description: Create and run a process with a double extension.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


MY_APP_EXE = "bin/myapp_x64.exe"


@register_code_rta(
    id="27694576-0454-40b3-9823-e29719c53750",
    name="process_double_extension",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="8b2b3a62-a598-4293-bc14-3d5fa22bb98f", name="Executable File Creation with Multiple Extensions"
        )
    ],
    techniques=["T1204", "T1036"],
    ancillary_files=[MY_APP_EXE],
)
def main():
    anomalies = ["test.txt.exe"]

    for path in anomalies:
        log.info(f"Masquerading process as {path}")
        _common.copy_file(MY_APP_EXE, path)
        _ = _common.execute_command([path])
        _common.remove_file(path)
