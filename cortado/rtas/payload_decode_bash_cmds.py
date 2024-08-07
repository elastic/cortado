# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="4406f514-0ffa-465b-9cef-2eeeb32f1096",
    name="payload_decode_bash_cmds",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="5dce3865-838f-4773-9781-87226af1fc12", name="Payload Decoded and Decrypted via Built-In Utilities"
        )
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    # create masquerades
    masquerade = "/tmp/DiskImageMounter"
    masquerade2 = "/tmp/bash"
    masquerade3 = "/tmp/openssl"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)
    _common.create_macos_masquerade(masquerade3)

    # Execute command
    _common.log("Launching fake bash with base64 decode commands")
    _common.execute([masquerade], timeout=10, kill=True)

    command = f"{masquerade3} enc -base64 -d"
    _common.execute([masquerade2, "childprocess", command, "/Volumes/test"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    _common.remove_file(masquerade3)
