# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ea7c50ad-5736-48c7-bf39-50f708710826",
    name="app_bundler_execution",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="94a891a9-3771-4a8c-a6ca-82fa66cfd7e2", name="Script Execution via macOS Application Bundle")
    ],
    techniques=["T1553", "T1059"],
)
def main():
    # create masquerades
    masquerade = "/tmp/launchd"
    masquerade2 = "/tmp/bash"
    masquerade3 = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)
    _common.create_macos_masquerade(masquerade3)

    # Execute command
    log.info("Launching fake macOS application bundler commands")
    command = f"{masquerade2} test.app/Contents/MacOS/test-psntest"
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10)
    _ = _common.execute_command(
        [masquerade2, "childprocess", masquerade3],
        timeout_secs=10,
    )

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
