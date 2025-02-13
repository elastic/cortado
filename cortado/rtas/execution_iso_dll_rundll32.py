# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

# iso contains shortcut to start Rundll32 to load a testing DLL that when executed it will spawn notepad.exe
ISO_FILE = "bin/lnk_from_iso_rundll.iso"
# shortcut name
LINK_FILE = "Invite.lnk"


@register_code_rta(
    id="8bd17f51-3fc0-46a8-9e1a-662723314ad4",
    name="execution_iso_dll_rundll32",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="779b9502-7912-4773-95a1-51cd702a71c8", name="Suspicious ImageLoad from an ISO Mounted Device"),
        RuleMetadata(id="08fba401-b76f-4c7b-9a88-4f3b17fe00c1", name="DLL Loaded from an Archive File"),
    ],
    techniques=["T1574", "T1574.002"],
)
def main():
    # ps script to mount, execute a file and unmount ISO device
    PS_SCRIPT = _common.get_resource_path("bin/ExecFromISOFile.ps1")

    if Path(ISO_FILE).is_file() and Path(PS_SCRIPT).is_file():
        log.info(f"ISO File {ISO_FILE} will be mounted and executed via powershell")

        # import ExecFromISO function that takes two args -ISOFIle pointing to ISO file path and -procname pointing to the filename to execute
        command = f"powershell.exe -ExecutionPol Bypass -c import-module {PS_SCRIPT}; ExecFromISO -ISOFile {ISO_FILE} -procname {LINK_FILE};"
        _ = _common.execute_command(command, shell=True)

        # terminate notepad.exe spawned as a result of the DLL execution
        _ = _common.execute_command(["taskkill", "/f", "/im", "notepad.exe"])
        log.info("RTA Done!")
