# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b4454817-eea7-458d-8426-e4f529352e39",
    name="discovery_builtin_cmd",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="92525741-9ca8-466e-acee-ceb14ab0dc34", name="System Discovery via Built-In Utilities")
    ],
)
def main():
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands for system discovery with builtin cmds")
    _ = _common.execute_command([masquerade, "testhdiutil test", "test perltest -test"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
