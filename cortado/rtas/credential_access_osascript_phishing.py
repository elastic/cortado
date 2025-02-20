# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="cc7b01f9-852c-4232-8c70-ada3fb5cc515",
    name="credential_access_osascript_phishing",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="318d3d9d-ba60-40e3-bc8c-3d3304209a3c", name="Potential Credentials Phishing via OSASCRIPT")
    ],
    siem_rules=[RuleMetadata(id="38948d29-3d5d-42e3-8aec-be832aaaf8eb", name="Prompt for Credentials with OSASCRIPT")],
    techniques=["T1056"],
)
def main():
    masquerade = "/tmp/osascript"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake osascript commands to display passwords")
    _ = _common.execute_command([masquerade, "osascript*display dialog*password*"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
