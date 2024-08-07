# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="bc6130d9-f4fd-46c6-bcfe-623be6c51a3b",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="10a500bb-a28f-418e-ba29-ca4c8d1a9f2f", name="WebProxy Settings Modification")],
    techniques=["T1539"],
)
def main():
    masquerade = "/tmp/networksetup"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake networksetup commands to configure webproxy settings")
    _common.execute([masquerade, "-setwebproxy"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
