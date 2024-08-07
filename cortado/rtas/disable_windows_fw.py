# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Disable Windows Firewall
# RTA: disable_windows_fw.py
# ATT&CK: T1089
# signal.rule.name: Disable Windows Firewall Rules via Netsh
# Description: Uses netsh.exe to backup, disable and restore firewall rules.

from pathlib import Path


@register_code_rta(
    id="75e14e5a-1188-47ea-9b96-2cf6e9443fc2",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="4b438734-3793-4fda-bd42-ceeada0be8f9", name="Disable Windows Firewall Rules via Netsh")
    ],
    techniques=["T1562"],
)
def main():
    _common.log("NetSH Advanced Firewall Configuration", log_type="~")
    netsh = "netsh.exe"

    rules_file = Path("fw.rules").resolve()

    # Check to be sure that fw.rules does not already exist from previously running this script
    _common.remove_file(rules_file)

    _common.log("Backing up rules")
    _common.execute([netsh, "advfirewall", "export", rules_file])

    _common.log("Disabling the firewall")
    _common.execute([netsh, "advfirewall", "set", "allprofiles", "state", "off"])

    _common.log("Undoing the firewall change", log_type="-")
    _common.execute([netsh, "advfirewall", "import", rules_file])

    _common.remove_file(rules_file)


