# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="9d02871f-6338-47aa-84c4-7d622692319f",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="396e1138-243c-4215-a8ed-be303204710d", name="Modification of Safari Settings via Defaults Command"
        )
    ],
    siem_rules=[
        RuleMetadata(
            id="6482255d-f468-45ea-a5b3-d3a7de1331ae", name="Modification of Safari Settings via Defaults Command"
        )
    ],
    techniques=["T1562"],
)
def main():
    masquerade = "/tmp/defaults"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching commands to mimic defaults modifying safari configurations.")
    _common.execute([masquerade, "write", "com.apple.Safari", "JavaScript"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
