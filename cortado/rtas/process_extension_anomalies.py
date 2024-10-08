# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Executable with Unusual Extensions
# RTA: process_extension_anomalies.py
# ATT&CK: T1036
# Description: Creates processes with anomalous extensions

import logging

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


MY_APP_EXE = "bin/myapp.exe"


@register_code_rta(
    id="c7d9d63d-09ff-40e9-b990-4c273281d6a0",
    name="process_extension_anomalies",
    platforms=[OSType.WINDOWS],
    ancillary_files=[MY_APP_EXE],
)
def main():
    anomalies = [
        "bad.pif",
        "evil.cmd",
        "evil.gif",
        "bad.pdf",
        "suspicious.bat",
        "hiding.vbs",
        "evil.xlsx",
    ]

    for path in anomalies:
        log.info(f"Masquerading python as {path}")
        _common.copy_file(MY_APP_EXE, path)
        _ = _common.execute_command(path, shell=True)
        _common.remove_file(path)
