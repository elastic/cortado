# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: USN Journal Deletion with fsutil.exe
# RTA: delete_usnjrnl.py
# ATT&CK: T1107
# signal.rule.name: Delete Volume USN Journal with Fsutil
# Description: Uses fsutil to delete the USN journal.

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5d049893-b5ca-4482-a9ea-c38c6d01c171",
    name="delete_usnjrnl",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="f675872f-6d85-40a3-b502-c0d2ef101e92", name="Delete Volume USN Journal with Fsutil")],
    techniques=["T1070"],
)
def main():
    message = "Deleting the USN journal may have unintended consequences"
    log.info("WARNING: %s" % message, log_type="!")
    time.sleep(2.5)
    _ = _common.execute_command(["fsutil", "usn", "deletejournal", "/d", "C:"])
