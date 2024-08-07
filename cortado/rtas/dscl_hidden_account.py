# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="b084e9dd-0c79-480c-b488-049ab8167b38",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="41b638a1-8ab6-4f8e-86d9-466317ef2db5", name="Potential Hidden Local User Account Creation")
    ],
    techniques=["T1078"],
)
def main():
    masquerade = "/tmp/dscl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake dscl commands to mimic creating a local hidden account.")
    _common.execute([masquerade, "IsHidden", "create", "true"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
