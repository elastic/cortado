# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="522a18d6-0c27-499f-86d9-cd421129a38d",
    name="plistbuddy_file_modification",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="901f0c30-a7c5-40a5-80e3-a50c6714432f", name="Suspicious Property List File Creation or Modification"
        )
    ],
    techniques=["T1547", "T1543"],
)
def main():
    masquerade = "/tmp/plistbuddy"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake plistbuddy command to modify plist files")
    _ = _common.execute_command([masquerade, "testRunAtLoad testLaunchAgentstest"], timeout_secs=10)
    _ = _common.execute_command(
        [masquerade, "testProgramArgumentstest"],
        timeout_secs=10,
    )

    # cleanup
    _common.remove_file(masquerade)
