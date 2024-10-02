# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="aec658cc-a5df-42e8-8e09-810b484b9ef2",
    name="curl_data_exfil",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="192ec591-1d00-4c16-a717-8a7481038d23", name="MacOS Potential Data Exfiltration via Curl")
    ],
    techniques=["T1048"],
)
def main():
    # create masquerades
    masquerade = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake curl commands to simulate data exfil")
    _ = _common.execute_command([masquerade, "-F", "*@*.zip", "http*"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
