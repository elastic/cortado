# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f9a34606-863d-46aa-b12d-eeeb68b530e3",
    name="networksetup_vpn",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="15dacaa0-5b90-466b-acab-63435a59701a", name="Virtual Private Network Connection Attempt")
    ],
    techniques=["T1021"],
)
def main():
    masquerade = "/tmp/networksetup"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake networksetup commands to connect to a VPN.")
    _ = _common.execute_command([masquerade, "-connectpppoeservice"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
