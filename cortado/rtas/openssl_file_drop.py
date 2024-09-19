# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2c2c75c0-28cc-4828-b8a4-6b33e027a80a",
    name="openssl_file_drop",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="d2017990-b448-4617-8d4a-55aa45abe354", name="Execution of a File Dropped by OpenSSL")
    ],
    siem_rules=[],
    techniques=["T1027", "T1140", "T1204", "T1204.002"],
)
def main():
    masquerade = "/tmp/testbin"

    # Execute command
    log.info("Launching bash commands for file creation via openssl")
    _ = _common.execute_command(["openssl", "rand", "-base64", 2, "-out", masquerade], timeout_secs=10)

    _common.create_macos_masquerade(masquerade)
    _ = _common.execute_command(
        [masquerade, "ls"],
        timeout_secs=10,
    )

    # cleanup
    _common.remove_file(masquerade)
