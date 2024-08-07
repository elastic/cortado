# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="23997dfa-9e30-4091-9ee2-8bd45a2da70a",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="5ae4e6f8-d1bf-40fa-96ba-e29645e1e4dc", name="Remote SSH Login Enabled via systemsetup Command")
    ],
    techniques=["T1021"],
)
def main():
    masquerade = "/tmp/systemsetup"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake systemsetup command to mimic enabling remote SSH.")
    _common.execute([masquerade, "-setremotelogin", "on"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
