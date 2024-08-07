# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="26339b1f-05ba-4fd8-94c2-8ee1613e4590",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="5d0265bf-dea9-41a9-92ad-48a8dcd05080", name="Persistence via Login or Logout Hook")],
    techniques=["T1037"],
)
def main():
    masquerade = "/tmp/defaults"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake defaults command to mimic installing a login hook.")
    _common.execute([masquerade, "write", "LoginHook"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
