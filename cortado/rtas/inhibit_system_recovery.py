# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b11e12a4-271c-427f-b215-12a7a25cb3be",
    name="inhibit_system_recovery",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="99358f31-a84a-4f92-bb91-4370083acda0", name="Inhibit System Recovery via Obfuscated Commands")
    ],
    techniques=["T1490", "T1047", "T1059"],
)
def main():
    log.info("Deleting volume shadow copies...")

    _ = _common.execute_command(
        [
            "powershell.exe",
            "Invoke-Expression",
            "-Command",
            "'vssadmin.exe",
            "delete",
            "shadows",
            "/for=c:",
            "/oldest",
            "/quiet'",
        ]
    )

    # Create a volume shadow copy so that there is at least one to delete
    _ = _common.execute_command(
        [
            "powershell.exe",
            "Invoke-Expression",
            "-Command",
            "'wmic.exe",
            "shadowcopy",
            "call",
            "create",
            "volume=c:\\'",
        ]
    )
    _ = _common.execute_command(
        [
            "powershell.exe",
            "Invoke-Expression",
            "-Command",
            "'wmic.exe",
            "shadowcopy",
            "delete",
            "/nointeractive'",
        ]
    )
