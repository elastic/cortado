# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7548a786-50f7-40e5-8f8a-b005e9e8d864",
    name="launchagent_plist",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="082e3f8c-6f80-485c-91eb-5b112cb79b28",
            name="Launch Agent Creation or Modification and Immediate Loading",
        )
    ],
    techniques=["T1543"],
)
def main():
    masquerade = "/tmp/launchctl"
    _common.create_macos_masquerade(masquerade)

    plist = f"{Path.home()}/Library/LaunchAgents/test.plist"
    _common.create_file_with_data(plist, "testing")

    # Execute command
    log.info("Launching fake launchctl command to mimic plist loading")
    _ = _common.execute_command([masquerade, "load"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
