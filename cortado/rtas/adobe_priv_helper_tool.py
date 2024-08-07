# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="e5d376ae-d634-41fa-903c-42f35736a615",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="f85ce03f-d8a8-4c83-acdc-5c8cd0592be7",
            name="Suspicious Child Process of Adobe Acrobat Reader Update Service",
        )
    ],
    techniques=["T1068"],
)
def main():
    masquerade = "/tmp/com.adobe.ARMDC.SMJobBlessHelper"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake com.adobe.ARMDC.SMJobBlessHelper commands to adobe mimic privesc")
    _common.execute([masquerade, "childprocess", masquerade], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
