# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="d5643e8a-c3f5-48a7-9f64-7255f603a24a",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="565c2b44-7a21-4818-955f-8d4737967d2e", name="Potential Admin Group Account Addition")],
    techniques=["T1078"],
)
def main():
    masquerade = "/tmp/dseditgroup"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake dseditgroup commands to mimic adding a user to an admin group")
    _common.execute([masquerade, "admin", "-append"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
