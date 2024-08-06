# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Persistent Scripts
# RTA: persistent_scripts.py
# ATT&CK: T1064 (Scripting), T1086 (PowerShell)

import os
import time
from pathlib import Path

from . import RtaMetadata, _common

metadata = RtaMetadata(
    id="2ab62c28-1abb-4ac5-a16d-2f4f75d01d02",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="afcce5ad-65de-4ed2-8516-5e093d3ac99a", name="Local Scheduled Task Creation")],
    techniques=["T1053"],
)


VBS = _common.get_path("bin", "persistent_script.vbs")
NAME = "rta-vbs-persistence"


@_common.requires_os(*metadata.platforms)
@_common.dependencies(_common.PS_EXEC, VBS)
def main():
    _common.log("Persistent Scripts")

    if _common.check_system():
        _common.log("Must be run as a non-SYSTEM user", log_type="!")
        return 1

    # Remove any existing profiles
    user_profile = os.environ["USERPROFILE"]
    log_file = Path(user_profile) / NAME / ".log"

    # Remove log file if exists
    _common.remove_file(log_file)

    _common.log("Running VBS")
    _common.execute(["cscript.exe", VBS])

    # Let the script establish persistence, then read the log file back
    time.sleep(5)
    _common.print_file(log_file)
    _common.remove_file(log_file)

    # Now trigger a 'logon' event which causes persistence to run
    _common.log("Simulating user logon and loading of profile")
    # _common.execute(["taskkill.exe", "/f", "/im", "explorer.exe"])
    # time.sleep(2)

    _common.execute(["C:\\Windows\\System32\\userinit.exe"], wait=True)
    _common.execute(["schtasks.exe", "/run", "/tn", NAME])

    # Wait for the "logon" to finish
    time.sleep(30)
    _common.print_file(log_file)

    # Now delete the user profile
    _common.log("Cleanup", log_type="-")
    _common.remove_file(log_file)
    _common.execute(["schtasks.exe", "/delete", "/tn", NAME, "/f"])


if __name__ == "__main__":
    exit(main())
