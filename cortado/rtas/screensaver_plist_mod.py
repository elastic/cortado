# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ce87d15a-9b72-42c4-8721-ae4bcff86a05",
    name="screensaver_plist_mod",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="ebae5222-71ba-4b73-afe9-8e034f8b4a04", name="Screensaver Plist File Modified by Unexpected Process"
        )
    ],
    siem_rules=[
        RuleMetadata(
            id="e6e8912f-283f-4d0d-8442-e0dcaf49944b", name="Screensaver Plist File Modified by Unexpected Process"
        )
    ],
    techniques=["T1546"],
)
def main():
    masquerade = "/tmp/killall"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake file screensaver plist modification commands")
    _common.create_file_with_data(
        "/Library/Managed Preferences/com.apple.screensaver.test.plist",
        "testing",
    )
    _ = _common.execute_command([masquerade, "cfprefsd"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
