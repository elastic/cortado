# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Invalid Process Trees in Windows
# RTA: unusual_parent_child.py
# signal.rule.name: Unusual Parent-Child Relationship
# ATT&CK: T1093
# Description: Runs several Windows core processes directly, instead of from the proper parent in Windows.

import logging
import sys
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6cf12026-f99f-4e5c-8cd4-3dbc7bce3e67",
    name="unusual_parent_child",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="35df0dd8-092d-4a83-88c1-5151a804f31b", name="Unusual Parent-Child Relationship")],
    techniques=["T1055"],
)
def main():
    log.info("Running Windows processes with an unexpected parent of %s" % Path(sys.executable).name)
    process_names = [
        # "C:\\Windows\\System32\\smss.exe", BSOD (avoid this)
        # "C:\\Windows\\System32\\csrss.exe", BSOD (avoid this)
        # "C:\\Windows\\System32\\wininit.exe", BSOD (avoid this)
        # "C:\\Windows\\System32\\services.exe", BSOD (avoid this)
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\lsass.exe",
        "C:\\Windows\\System32\\taskhost.exe",  # Win7
        "C:\\Windows\\System32\\taskhostw.exe",  # Win10
        "C:\\Windows\\System32\\svchost.exe",
    ]

    for process in process_names:
        # taskhostw.exe isn't on all versions of windows
        if Path(process).is_file():
            _ = _common.execute_command(process, shell=True, timeout_secs=2)
        else:
            log.info("Skipping %s" % process, "-")
