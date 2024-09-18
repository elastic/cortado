# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f158a6dc-1974-4b98-a3e7-466f6f1afe01",
    name="keychain_dump",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="565d6ca5-75ba-4c82-9b13-add25353471c", name="Dumping of Keychain Content via Security Command")
    ],
    techniques=["T1555"],
)
def main():
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands to dump keychain credentials")
    _ = _common.execute_command([masquerade, "dump-keychain", "-d"], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
