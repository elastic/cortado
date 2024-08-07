# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="de7e28b2-c01d-4cd7-abb7-ddb64bce5f45",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="24fa0f80-7e3a-4b27-801a-30ef53f190bf", name="Compressed File Extracted to Temp Directory")
    ],
    siem_rules=[],
    techniques=["T1059", "T1059.004"],
)
def main():
    masquerade = "/Users/bash"
    _common.create_macos_masquerade(masquerade)

    command = 'bash -c "unzip * /tmp/* -d *"'

    _common.log("Executing unzip to tmp directory.")
    _common.execute([masquerade, "childprocess", command], shell=True, timeout=5, kill=True)
