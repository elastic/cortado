# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e5d376ae-d634-41fa-903c-42f35736a615",
    name="adobe_priv_helper_tool",
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
    log.info("Launching fake com.adobe.ARMDC.SMJobBlessHelper commands to adobe mimic privesc")
    _ = _common.execute_command([masquerade, "childprocess", masquerade], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
