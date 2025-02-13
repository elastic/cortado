# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Memory Dump via Comsvcs
# RTA: comsvcs_dump.py
# ATT&CK: T1117
# Description: Invokes comsvcs.dll with rundll32.exe to mimic creating a process MiniDump.

import logging
import os
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="413cf7ef-0fad-46fd-ab67-e94c4e3e0f0b",
    name="comsvcs_dump",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="c5c9f591-d111-4cf8-baec-c26a39bc31ef", name="Potential Credential Access via Renamed COM+ Services DLL"
        ),
        RuleMetadata(id="208dbe77-01ed-4954-8d44-1e5751cb20de", name="LSASS Memory Dump Handle Access"),
        RuleMetadata(
            id="00140285-b827-4aee-aa09-8113f58a08f3", name="Potential Credential Access via Windows Utilities"
        ),
    ],
    techniques=["T1003"],
)
def main():
    log.info("Memory Dump via Comsvcs")
    pid = os.getpid()
    _ = _common.execute_command(
        [
            "powershell.exe",
            "-c",
            "rundll32.exe",
            "C:\\Windows\\System32\\comsvcs.dll",
            "MiniDump",
            "{} dump.bin full".format(pid),
        ]
    )
    time.sleep(1)
    _common.remove_file("dump.bin")
