# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c0f3618b-a7d9-403c-8b42-572da0b20f47",
    name="shlayer_payload",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="3dda1ac2-86ef-41f5-ad3b-d9396383e104", name="Shlayer Malware Infection")],
    techniques=["T1105"],
)
def main():
    masquerade = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake curl command to download Shlayer payloads")
    _ = _common.execute_command([masquerade, "-f0L"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
