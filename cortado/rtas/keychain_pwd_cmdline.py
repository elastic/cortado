# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="f964558b-0674-4c97-afcc-42d4b6a813c6",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "Web Browsers Password Access via Command Line",
            "rule_id": "77d71ede-3025-4c71-bb99-ada7c344bf89",
        }
    ],
    siem_rules=[
        RuleMetadata(id="9092cd6c-650f-4fa3-8a8a-28256c7489c9", name="Keychain Password Retrieval via Command Line")
    ],
    techniques=["T1555"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/security"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake commands to collect credentials")
    _common.execute([masquerade, "-wa", "find-generic-password", "Chrome"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
