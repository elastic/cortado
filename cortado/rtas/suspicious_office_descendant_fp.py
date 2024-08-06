# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Emulate Suspect MS Office Child Processes
# RTA: suspect_office_children.py
# ATT&CK: T1064
# Description: Generates various children processes from emulated Office processes.

from pathlib import Path
import time

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="e6d124ee-27d3-48a6-8c59-354072ec9e00",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{"rule_id": "a624863f-a70d-417f-a7d2-7a404638d47f", "rule_name": "Suspicious MS Office Child Process"}],
    techniques=["T1566"],
)


@_common.requires_os(*metadata.platforms)
def main():
    _common.log("MS Office unusual child process emulation")
    suspicious_apps = [
        "msiexec.exe /i blah /quiet",
        "powershell.exe exit",
        "wscript.exe //b",
    ]
    cmd_path = "c:\\windows\\system32\\cmd.exe"
    browser_path = Path("firefox.exe").resolve()
    _common.copy_file(cmd_path, browser_path)

    for office_app in ["winword.exe", "excel.exe"]:

        _common.log("Emulating %s" % office_app)
        office_path = Path(office_app).resolve()
        _common.copy_file(cmd_path, office_path)

        for command in suspicious_apps:
            _common.execute(
                "%s /c %s /c %s" % (office_path, browser_path, command),
                timeout=5,
                kill=True,
            )

        _common.log("Cleanup %s" % office_path)
        _common.remove_file(office_path)

    _common.log("Sleep 5 to allow processes to finish")
    time.sleep(5)
    _common.log("Cleanup %s" % browser_path)
    _common.remove_file(browser_path)


if __name__ == "__main__":
    exit(main())
