# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="eb5834cf-fcd8-4318-a656-5315a664e61d",
    name="link_to_tmp",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="ccca5e9f-2625-4b95-9b15-d5d8fc56df2c", name="Link Creation to Temp Directory"),
    ],
    siem_rules=[],
    techniques=["T1222", "T1222.002"],
)
def main():
    masquerade = "/tmp/ln"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake ln commands to link to temp directory")
    with _common.temporary_file("testing", "/tmp/test.txt"):
        _ = _common.execute_command([masquerade, "-s", "/tmp/test.txt"], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
