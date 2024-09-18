# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c5cecd6d-a7c4-4e3b-970d-6ca5cfc5c662",
    name="unshadow_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="05f95917-6942-4aab-a904-37c6db906503", name="Potential Linux Credential Dumping via Unshadow")
    ],
    siem_rules=[
        RuleMetadata(id="e7cb3cfd-aaa3-4d7b-af18-23b89955062c", name="Potential Linux Credential Dumping via Unshadow")
    ],
    techniques=["T1003", "T1003.008"],
)
def main():
    masquerade = "/tmp/unshadow"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake commands to dump credential via unshadow")
    _ = _common.execute_command([masquerade, "/etc/passwd /etc/shadow"], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
