# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a18454da-5f28-4223-95d6-5dc1f58c861a",
    name="env_variable_hijacking",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="7453e19e-3dbf-4e4e-9ae0-33d6c6ed15e1", name="Modification of Environment Variable via Launchctl"
        )
    ],
    techniques=["T1574"],
)
def main():
    masquerade = "/tmp/launchctl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake launchctl command to mimic env variable hijacking")
    _ = _common.execute_command([masquerade, "setenv"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
