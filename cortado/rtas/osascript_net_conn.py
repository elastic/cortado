# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="66407efa-a32e-4f4d-b339-def48e23e810",
    name="osascript_net_conn",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="47f76567-d58a-4fed-b32b-21f571e28910", name="Apple Script Execution followed by Network Connection"
        )
    ],
    techniques=["T1105", "T1059"],
)
def main():
    masquerade = "/tmp/osascript"
    _common.copy_file("/usr/bin/curl", masquerade)

    # Execute command
    log.info("Launching fake commands to mimic creating a network connection with osascript")
    _ = _common.execute_command([masquerade, "portquiz.net"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
