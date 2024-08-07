# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="d7a67c3c-eadb-4bfb-beb1-61ddd86b4b83",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_id": "6e47b750-72c4-4af9-ad7b-0fc846df64d3",
            "rule_name": "Quarantine Attribute Deleted via Untrusted Binary",
        }
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    # create masquerades
    masquerade = "/tmp/bash"
    masquerade2 = "/tmp/testbypass"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute commands
    _common.log("Launching fake delete commands to delete quarantine attribute.")
    command = f"{masquerade} xattr -d com.apple.quarantine"
    _common.execute([masquerade2, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)


