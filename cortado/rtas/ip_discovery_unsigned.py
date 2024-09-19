# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5e1ca4f9-16cc-4dd3-bfba-4bd5c7579f4a",
    name="ip_discovery_unsigned",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="dfe28e03-9b0b-47f5-9753-65ed2666663f", name="External IP Address Discovery via Untrusted Program"
        )
    ],
    siem_rules=[],
    techniques=["T1016"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    log.info("Retrieving the public IP Address using ipify")
    _ = _common.execute_command([posh, "/c", "iwr", "http://api.ipify.org/", "-UseBasicParsing"], timeout_secs=10)
    _common.remove_file(posh)
