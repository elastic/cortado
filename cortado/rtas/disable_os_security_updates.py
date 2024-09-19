# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f4e4a28e-c845-4b26-bfdf-24128e73ef21",
    name="disable_os_security_updates",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="741ad90d-e8d0-4d29-b91b-3d68108cb789", name="Operating System Security Updates Disabled")
    ],
    siem_rules=[
        RuleMetadata(id="f683dcdf-a018-4801-b066-193d4ae6c8e5", name="SoftwareUpdate Preferences Modification")
    ],
    techniques=["T1562"],
)
def main():
    masquerade = "/tmp/defaults"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands for system discovery with builtin cmds")

    # ER
    _ = _common.execute_command(
        [
            masquerade,
            "write",
            "-bool",
            "com.apple.SoftwareUpdate",
            "CriticalUpdateInstall",
            "NO",
        ],
        timeout_secs=10,
    )

    # DR
    _ = _common.execute_command(
        [masquerade, "write", "-bool", "com.apple.SoftwareUpdate", "NO"],
        timeout_secs=10,
    )

    # cleanup
    _common.remove_file(masquerade)
