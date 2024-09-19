# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="057f2c1b-28cc-4286-92ce-75e789aa8e74",
    name="bifrost_attack",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="fecebe4f-2d28-46e7-9bc1-71cdd8ecdd60", name="Potential Kerberos Attack via Bifrost")
    ],
    siem_rules=[RuleMetadata(id="16904215-2c95-4ac8-bf5c-12354e047192", name="Potential Kerberos Attack via Bifrost")],
    techniques=["T1558", "T1550"],
)
def main():
    masquerade = "/tmp/bifrost"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake bifrost attack with kerberoast commands")
    _ = _common.execute_command([masquerade, "-action", "-kerberoast"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
