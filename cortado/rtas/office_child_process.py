# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="65ae1bcd-0b1c-4992-97c3-f40b0f92deb1",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="66da12b1-ac83-40eb-814c-07ed1d82b7b9", name="Suspicious macOS MS Office Child Process")
    ],
    techniques=["T1566"],
)
def main():
    # create masquerades
    masquerade = "/tmp/Microsoft Word"
    masquerade2 = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    _common.log("Executing fake Microsoft commands to mimic suspicious child processes.")
    _common.execute([masquerade, "childprocess", masquerade2], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)


