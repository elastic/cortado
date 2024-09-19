# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="bc6130d9-f4fd-46c6-bcfe-623be6c51a3b",
    name="webproxy_modification",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="10a500bb-a28f-418e-ba29-ca4c8d1a9f2f", name="WebProxy Settings Modification")],
    techniques=["T1539"],
)
def main():
    masquerade = "/tmp/networksetup"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake networksetup commands to configure webproxy settings")
    _ = _common.execute_command([masquerade, "-setwebproxy"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
