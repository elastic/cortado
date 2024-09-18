# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="fd86ee85-a3ee-4824-875b-bb386a23a578",
    name="openssl_decode_payload",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="4dd92062-2871-43bc-adda-82f15cf6e189", name="Decoded or Decrypted Payload Written to Temp Directory"
        )
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    masquerade = "/tmp/openssl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake openssl commands to decode payload")
    _ = _common.execute_command([masquerade, "-out", "/tmp/test", "enc", "-d"], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
