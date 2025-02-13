# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Shortcut File Suspicious Process
# RTA: shortcut_file_suspicious_process.py
# ATT&CK: T1023,T1204,T1193,T1192
# Description: Create a .lnk file using cmd.exe

import logging

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="755e88fd-1fe1-44c7-b5f0-688a39fec420",
    name="shortcut_file_suspicious_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    techniques=[],
)
def main():
    log.info("Writing dummy shortcut file")
    shortcut_path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\evil.lnk"
    _ = _common.execute_command(["cmd", "/c", "echo", "dummy_shortcut", ">", shortcut_path])

    log.info("Deleting dummy shortcut file")
    _common.remove_file(shortcut_path)
