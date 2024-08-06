# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Persistence using GlobalFlags
# RTA: globalflags.py
# ATT&CK: T1183
# Description: Uses GlobalFlags option in Image File Execution Options to silently execute calc.exe after the monitored
#              process (notepad.exe) is closed.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="e09d904a-f3bb-4d36-8eb8-8c234812807c",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="6839c821-011d-43bd-bd5b-acff00257226", name="Image File Execution Options Injection")],
    techniques=["T1546"],
)


@_common.requires_os(*metadata.platforms)
def main():
    _common.log("Setting up persistence using Globalflags")
    ifeo_subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\netstat.exe"
    spe_subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\netstat.exe"

    with _common.temporary_reg(_common.HKLM, ifeo_subkey, "GlobalFlag", 512, _common.DWORD), _common.temporary_reg(
        _common.HKLM, spe_subkey, "ReportingMode", 1, _common.DWORD
    ), _common.temporary_reg(_common.HKLM, spe_subkey, "MonitorProcess", "C:\\Windows\\system32\\whoami.exe"):

        _common.log("Opening and closing netstat")
        _common.execute(["whoami"], shell=True)
        _common.execute(["taskkill", "/F", "/IM", "netstat.exe"])


if __name__ == "__main__":
    exit(main())
