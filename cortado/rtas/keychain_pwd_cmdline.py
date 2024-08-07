# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="f964558b-0674-4c97-afcc-42d4b6a813c6",
    name="keychain_pwd_cmdline",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="77d71ede-3025-4c71-bb99-ada7c344bf89", name="Web Browsers Password Access via Command Line")
    ],
    siem_rules=[
        RuleMetadata(id="9092cd6c-650f-4fa3-8a8a-28256c7489c9", name="Keychain Password Retrieval via Command Line")
    ],
    techniques=["T1555"],
)
def main():
    masquerade = "/tmp/security"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake commands to collect credentials")
    _common.execute([masquerade, "-wa", "find-generic-password", "Chrome"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
