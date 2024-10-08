# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d7a67c3c-eadb-4bfb-beb1-61ddd86b4b83",
    name="delete_quarantine_attrib",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="6e47b750-72c4-4af9-ad7b-0fc846df64d3", name="Quarantine Attribute Deleted via Untrusted Binary"
        )
    ],
)
def main():
    # create masquerades
    masquerade = "/tmp/bash"
    masquerade2 = "/tmp/testbypass"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute commands
    log.info("Launching fake delete commands to delete quarantine attribute.")
    command = f"{masquerade} xattr -d com.apple.quarantine"
    _ = _common.execute_command([masquerade2, "childprocess", command],) timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
