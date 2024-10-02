# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d64b9c0c-d4be-4af2-b820-233493fb7d75",
    name="inhibit_system_recovery_cmd",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="d3588fad-43ae-4f2d-badd-15a27df72133", name="Inhibit System Recovery via Windows Command Shell"
        )
    ],
    techniques=["T1490", "T1047", "T1059"],
)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"

    # Execute command
    log.info("Deleting Shadow Copies using Vssadmin spawned by cmd")
    _ = _common.execute_command([cmd, "/c", vssadmin, "delete", "shadows", "/For=C:"], timeout_secs=10)
