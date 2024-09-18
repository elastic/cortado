# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Emulate MS Office Dropping an executable file to disk
# RTA: ms_office_drop_exe.py
# ATT&CK: T1064
# Description: MS Office writes executable file and it is run.

import logging
import os
import time
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="ce85674f-fb6c-44d5-b880-4ce9062e1028",
    name="ms_office_drop_exe",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="0d8ad79f-9025-45d8-80c1-4f0cd3c5e8e5", name="Execution of File Written or Modified by Microsoft Office"
        )
    ],
    techniques=["T1566"],
)
def main():
    cmd_path = "c:\\windows\\system32\\cmd.exe"

    for office_app in ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]:
        log.info("Emulating office application %s" % office_app)
        office_path = Path(office_app).resolve()
        _common.copy_file(cmd_path, office_path)

        bad_path = Path("bad-{}-{}.exe".format(hash(office_app), os.getpid())).resolve()
        _ = _common.execute_command([office_path, "/c", "copy", cmd_path, bad_path])

        time.sleep(1)
        _ = _common.execute_command([bad_path, "/c", "whoami"])

        # cleanup
        time.sleep(1)
        _common.remove_files([office_app, bad_path])
        print("")
