# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="cf71bf97-e3ba-474c-9b6b-538e5a8008b0",
    name="spctl_gatekeeper_bypass",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="4da13d6e-904f-4636-81d8-6ab14b4e6ae9", name="Attempt to Disable Gatekeeper")],
    techniques=["T1553"],
)
def main():
    masquerade = "/tmp/spctl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Executing fake spctl for Gatekeeper defensive evasion.")
    _ = _common.execute_command([masquerade, "spctl", "--master-disable"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
