# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9332cece-38b7-49e1-9f8d-e879913ffdfb",
    name="exec_tclsh",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="ac1eaed8-2aee-48d7-9824-2be1f00eda0e", name="Tclsh execution followed by immediate network connection"
        )
    ],
    siem_rules=[],
    techniques=["T1059"],
)
def main():
    url = "http://localhost.localhost"
    masquerade = "/tmp/tclsh"
    _common.copy_file("/usr/bin/curl", masquerade)

    log.info("Executing commands to mimic network activity from tclsh")
    _ = _common.execute_command([masquerade, url], shell=True)
