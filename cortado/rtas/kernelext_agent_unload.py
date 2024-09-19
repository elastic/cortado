# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="61f308d8-40c5-4c46-9181-e993cf07e92b",
    name="kernelext_agent_unload",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="a412fd9b-2a06-49ff-a073-8eb313c2d930",
            name="Attempt to Unload Elastic Endpoint Security Kernel Extension",
        )
    ],
    siem_rules=[
        RuleMetadata(
            id="70fa1af4-27fd-4f26-bd03-50b6af6b9e24",
            name="Attempt to Unload Elastic Endpoint Security Kernel Extension",
        )
    ],
    techniques=["T1547", "T1562"],
)
def main():
    masquerade = "/tmp/kextunload"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake kernel ext commands to unload elastic agent")
    _ = _common.execute_command([masquerade, "EndpointSecurity.kext"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
