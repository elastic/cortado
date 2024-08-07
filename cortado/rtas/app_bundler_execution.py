# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="ea7c50ad-5736-48c7-bf39-50f708710826",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="94a891a9-3771-4a8c-a6ca-82fa66cfd7e2", name="Script Execution via macOS Application Bundle")
    ],
    siem_rules=[],
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
    _common.log("Launching fake macOS application bundler commands")
    command = f"{masquerade2} test.app/Contents/MacOS/test-psntest"
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True)
    _common.execute([masquerade2, "childprocess", masquerade3], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
