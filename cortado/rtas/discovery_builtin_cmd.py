# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="b4454817-eea7-458d-8426-e4f529352e39",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="92525741-9ca8-466e-acee-ceb14ab0dc34", name="System Discovery via Built-In Utilities")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake commands for system discovery with builtin cmds")
    _common.execute([masquerade, "testhdiutil test", "test perltest -test"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
