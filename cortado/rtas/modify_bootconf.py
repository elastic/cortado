# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="672cd0e6-fa5a-468f-80c8-04f92bead469",
    name="modify_bootconf",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="6d660b32-23bf-434b-a588-1cdc91224664", name="BCDEdit Safe Mode Command Execution")
    ],
    siem_rules=[],
    techniques=["T1490", "T1218", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed.exe")

    binary = "winword.exe"
    _common.copy_file(EXE_FILE, binary)
    bcdedit = "bcdedit.exe"

    # Messing with the boot configuration is not a great idea so create a backup:
    log.info("Exporting the boot configuration....")
    backup_file = Path("boot.cfg").resolve()
    _ = _common.execute_command([bcdedit, "/export", backup_file])

    # WARNING: this sets up computer to boot into Safe Mode upon reboot
    log.info("Changing boot configuration", log_type="!")
    _ = _common.execute_command([binary, "/c", bcdedit, "/set", "{default}", "safeboot", "minimal"])

    # Delete value to not boot into Safe Mode
    log.info("Reset boot configuration", log_type="!")
    _ = _common.execute_command([binary, "/c", bcdedit, "/deletevalue", "safeboot"])

    # Restore the boot configuration
    log.info("Restoring boot configuration from %s" % backup_file, log_type="-")
    _ = _common.execute_command([bcdedit, "/import", backup_file])

    _common.remove_files([binary])
