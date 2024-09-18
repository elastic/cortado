# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Boot Config Deletion With bcdedit
# RTA: delete_bootconf.py
# ATT&CK: T1107
# signal.rule.name: Modification of Boot Configuration
# Description: Uses bcdedit.exe to backup the current boot configuration, and then to delete the current boot
#  configuration, finally restoring the original.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="eaf71384-2e38-4970-b170-9645ccde1d2b",
    name="delete_bootconf",
    platforms=[OSType.WINDOWS],
    siem_rules=[RuleMetadata(id="69c251fb-a5d6-4035-b5ec-40438bd829ff", name="Modification of Boot Configuration")],
    techniques=["T1490"],
)
def main():
    # Messing with the boot configuration is probably not a great idea so create a backup:
    log.info("Exporting the boot configuration....")
    bcdedit = "bcdedit.exe"
    backup_file = Path("boot.cfg").resolve()
    _ = _common.execute_command(["bcdedit.exe", "/export", backup_file])

    # WARNING: this is a destructive command which might be super bad to run
    log.info("Changing boot configuration", log_type="!")
    _ = _common.execute_command([bcdedit, "/set", "{current}", "bootstatuspolicy", "ignoreallfailures"])
    _ = _common.execute_command([bcdedit, "/set", "{current}", "recoveryenabled", "no"])

    # Restore the boot configuration
    log.info("Restoring boot configuration from %s" % backup_file, log_type="-")
    _ = _common.execute_command([bcdedit, "/import", backup_file])
