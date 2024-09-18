# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="adc70542-4d6e-4449-bf96-4cd44367bfbb",
    name="screensaver_child_process",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="fba012f6-7aa8-448e-8f59-cdecce2845b5", name="Unexpected Child Process of macOS Screensaver Engine"
        )
    ],
    siem_rules=[
        RuleMetadata(
            id="48d7f54d-c29e-4430-93a9-9db6b5892270", name="Unexpected Child Process of macOS Screensaver Engine"
        )
    ],
    techniques=["T1546"],
)
def main():
    masquerade = "/tmp/ScreenSaverEngine"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands to spawn bash from screensaver engine")
    _ = _common.execute_command([masquerade], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
