# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Registry persistence creation
# RTA: registry_persistence_create.py
# signal.rule.name: Local Service Commands
# signal.rule.name: Potential Modification of Accessibility Binaries
# ATT&CK: T1015, T1103
# Description: Creates registry persistence for mock malware in Run and RunOnce keys, Services, NetSH and debuggers.

# TODO: Split into multiple files
import time

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="c62c65bf-248e-4f5a-ad4f-a48736c1d6f2",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_id": "7405ddf1-6c8e-41ce-818f-48bea6bcaed8",
            "rule_name": "Potential Modification of Accessibility Binaries",
        }
    ],
    techniques=["T1546"],
)


TARGET_APP = _common.get_path("bin", "myapp.exe")


def pause():
    time.sleep(0.5)


@_common.requires_os(*metadata.platforms)
@_common.dependencies(TARGET_APP)
def main():
    _common.log("Suspicious Registry Persistence")
    winreg = _common.get_winreg()

    for hive in (_common.HKLM, _common.HKCU):
        _common.write_reg(
            hive,
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\",
            "RunOnceTest",
            TARGET_APP,
        )
        _common.write_reg(
            hive,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
            "RunTest",
            TARGET_APP,
        )

    # create Services subkey for "ServiceTest"
    _common.log("Creating ServiceTest registry key")
    hklm = winreg.HKEY_LOCAL_MACHINE
    hkey = winreg.CreateKey(hklm, "System\\CurrentControlSet\\Services\\ServiceTest\\")

    # create "ServiceTest" data values
    _common.log("Updating ServiceTest metadata")
    winreg.SetValueEx(hkey, "Description", 0, winreg.REG_SZ, "A fake service")
    winreg.SetValueEx(hkey, "DisplayName", 0, winreg.REG_SZ, "ServiceTest Service")
    winreg.SetValueEx(hkey, "ImagePath", 0, winreg.REG_SZ, "c:\\ServiceTest.exe")
    winreg.SetValueEx(hkey, "ServiceDLL", 0, winreg.REG_SZ, "C:\\ServiceTest.dll")

    # modify contents of ServiceDLL and ImagePath
    _common.log("Modifying ServiceTest binary")
    winreg.SetValueEx(hkey, "ImagePath", 0, winreg.REG_SZ, "c:\\ServiceTestMod.exe")
    winreg.SetValueEx(hkey, "ServiceDLL", 0, winreg.REG_SZ, "c:\\ServiceTestMod.dll")

    hkey.Close()
    _common.pause()

    # delete Service subkey for "ServiceTest"
    _common.log("Removing ServiceTest", log_type="-")
    hkey = winreg.CreateKey(hklm, "System\\CurrentControlSet\\Services\\")
    winreg.DeleteKeyEx(hkey, "ServiceTest")

    hkey.Close()
    _common.pause()

    # Additional persistence
    _common.log("Adding AppInit DLL")
    windows_base = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\"
    _common.write_reg(_common.HKLM, windows_base, "AppInit_Dlls", "evil.dll", restore=True, pause=True)

    _common.log("Adding AppCert DLL")
    appcertdlls_key = "System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"
    _common.write_reg(_common.HKLM, appcertdlls_key, "evil", "evil.dll", restore=True, pause=True)

    debugger_targets = [
        "normalprogram.exe",
        "sethc.exe",
        "utilman.exe",
        "magnify.exe",
        "narrator.exe",
        "osk.exe",
        "displayswitch.exe",
        "atbroker.exe",
    ]

    for victim in debugger_targets:
        _common.log("Registering Image File Execution Options debugger for %s -> %s" % (victim, TARGET_APP))
        base_key = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s" % victim
        _common.write_reg(_common.HKLM, base_key, "Debugger", TARGET_APP, restore=True)

    # create new NetSh key value
    _common.log("Adding a new NetSh Helper DLL")
    key = "Software\\Microsoft\\NetSh"
    _common.write_reg(_common.HKLM, key, "BadHelper", "c:\\windows\\system32\\BadHelper.dll")

    # modify the list of SSPs
    _common.log("Adding a new SSP to the list of security packages")
    key = "System\\CurrentControlSet\\Control\\Lsa"
    _common.write_reg(
        _common.HKLM,
        key,
        "Security Packages",
        ["evilSSP"],
        _common.MULTI_SZ,
        append=True,
        pause=True,
    )

    hkey.Close()
    pause()


if __name__ == "__main__":
    exit(main())
