# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Disable Windows Firewall
# RTA: disable_windows_fw.py
# ATT&CK: T1089
# signal.rule.name: Disable Windows Firewall Rules via Netsh
# Description: Uses netsh.exe to backup, disable and restore firewall rules.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="75e14e5a-1188-47ea-9b96-2cf6e9443fc2",
    name="disable_windows_fw",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="4b438734-3793-4fda-bd42-ceeada0be8f9", name="Disable Windows Firewall Rules via Netsh")
    ],
    techniques=["T1562"],
)
def main():
    log.info("NetSH Advanced Firewall Configuration", log_type="~")
    netsh = "netsh.exe"

    rules_file = Path("fw.rules").resolve()

    # Check to be sure that fw.rules does not already exist from previously running this script
    _common.remove_file(rules_file)

    log.info("Backing up rules")
    _ = _common.execute_command([netsh, "advfirewall", "export", rules_file])

    log.info("Disabling the firewall")
    _ = _common.execute_command([netsh, "advfirewall", "set", "allprofiles", "state", "off"])

    log.info("Undoing the firewall change", log_type="-")
    _ = _common.execute_command([netsh, "advfirewall", "import", rules_file])

    _common.remove_file(rules_file)
