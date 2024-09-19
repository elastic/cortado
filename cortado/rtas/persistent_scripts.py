# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Persistent Scripts
# RTA: persistent_scripts.py
# ATT&CK: T1064 (Scripting), T1086 (PowerShell)

import logging
import os
import time
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

VBS = "bin/persistent_script.vbs"
NAME = "rta-vbs-persistence"


@register_code_rta(
    id="2ab62c28-1abb-4ac5-a16d-2f4f75d01d02",
    name="persistent_scripts",
    platforms=[OSType.WINDOWS],
    siem_rules=[RuleMetadata(id="afcce5ad-65de-4ed2-8516-5e093d3ac99a", name="Local Scheduled Task Creation")],
    techniques=["T1053"],
    ancillary_files=[VBS, _common.PS_EXEC_EXE],
)
def main():
    log.info("Persistent Scripts")

    if _common.is_system():
        log.info("Must be run as a non-SYSTEM user")
        raise _common.ExecutionError("RTA must be run as a non-SYSTEM user")

    # Remove any existing profiles
    user_profile = os.environ["USERPROFILE"]
    log_file = Path(user_profile) / NAME / ".log"

    # Remove log file if exists
    _common.remove_file(log_file)

    log.info("Running VBS")
    _ = _common.execute_command(["cscript.exe", VBS])

    # Let the script establish persistence, then read the log file back
    time.sleep(5)
    _common.print_file(log_file)
    _common.remove_file(log_file)

    # Now trigger a 'logon' event which causes persistence to run
    log.info("Simulating user logon and loading of profile")
    # _common.execute(["taskkill.exe", "/f", "/im", "explorer.exe"])
    # time.sleep(2)

    _ = _common.execute_command(["C:\\Windows\\System32\\userinit.exe"])
    _ = _common.execute_command(["schtasks.exe", "/run", "/tn", NAME])

    # Wait for the "logon" to finish
    time.sleep(30)
    _common.print_file(log_file)

    # Now delete the user profile
    log.info("Cleanup")
    _common.remove_file(log_file)
    _ = _common.execute_command(["schtasks.exe", "/delete", "/tn", NAME, "/f"])
