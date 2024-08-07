# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="1b681241-d9f1-4239-a9e7-650ebc0c38a4",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="8e88d216-af7a-4f5c-8155-fa7d2be03987", name="Suspicious Terminal Child Process Execution")
    ],
    techniques=["T1059", "T1059.004"],
)
def main():
    masquerade = "/tmp/terminal"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    command = f"bash -c '/tmp/*'"
    _common.log("Launching bash commands to mimic terminal activity")
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
