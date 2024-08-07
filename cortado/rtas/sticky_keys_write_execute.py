# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Overwrite Accessibiity Binaries
# RTA: sticky_keys_write_execute.py
# signal.rule.name: Potential Modification of Accessibility Binaries
# signal.rule.name: Local Service Commands
# signal.rule.name: Persistence via TelemetryController Scheduled Task Hijack
# ATT&CK: T1015
# Description: Writes different binaries into various accessibility locations.

import time
from pathlib import Path


@register_code_rta(
    id="398933ec-f8d4-4d81-93ed-e7d7adcb9d97",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_id": "7405ddf1-6c8e-41ce-818f-48bea6bcaed8",
            "rule_name": "Potential Modification of Accessibility Binaries",
        },
        {
            "rule_id": "68921d85-d0dc-48b3-865f-43291ca2c4f2",
            "rule_name": "Persistence via TelemetryController Scheduled Task Hijack",
        },
    ],
    techniques=["T1546", "T1053"],
)
def main():
    # Prep
    bins = [
        "sethc.exe",
        "utilman.exe",
        "narrator.exe",
        "magnify.exe",
        "osk.exe",
        "displayswitch.exe",
        "atbroker.exe",
    ]
    calc = Path("\\windows\\system32\\calc.exe").resolve()
    temp = Path("temp.exe").resolve()

    # loop over bins
    for bin_name in bins:
        bin_path = Path("\\Windows\\system32\\" + bin_name).resolve()

        # Back up bin
        _common.copy_file(bin_path, temp)

        # Change Permissions to allow modification
        _common.execute(["takeown", "/F", bin_path, "/A"])
        _common.execute(["icacls", bin_path, "/grant", "Administrators:F"])

        # Copy Calc to overwrite binary, then run it
        _common.copy_file(calc, bin_path)
        _common.execute(bin_path, kill=True, timeout=1)

        # Restore Original File and Permissions on file
        _common.copy_file(temp, bin_path)
        _common.execute(["icacls", bin_path, "/setowner", "NT SERVICE\\TrustedInstaller"])
        _common.execute(["icacls", bin_path, "/grant:r", "Administrators:RX"])
        _common.remove_file(temp)

    # Cleanup
    time.sleep(2)
    _common.execute(["taskkill", "/F", "/im", "calculator.exe"])


if __name__ == "__main__":
    exit(main())
