# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="20631e46-d3c4-45c0-bfa8-37f6b287db36",
    name="execution_node_child_process",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="1d43f87d-2466-4714-8fef-d52816cc25fb", name="Execution via Electron Child Process Node.js Module"
        )
    ],
    siem_rules=[
        RuleMetadata(
            id="35330ba2-c859-4c98-8b7f-c19159ea0e58", name="Execution via Electron Child Process Node.js Module"
        )
    ],
    techniques=["T1548", "T1059"],
)
def main():
    masquerade = "/tmp/node"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Spawning fake node commands to mimic Electon child process.")
    _common.execute(
        [masquerade, "-e", "const { fork } = require('child_process');"],
        timeout=10,
        kill=True,
    )

    # cleanup
    _common.remove_file(masquerade)
