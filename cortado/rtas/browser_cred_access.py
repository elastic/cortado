# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ea187b1f-4aa0-4ffc-bac9-9ee1d55552fd",
    name="browser_cred_access",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="cea870d6-e6ee-4435-bc80-2c80e834c5d1", name="Suspicious Access to Stored Browser Credentials")
    ],
    siem_rules=[RuleMetadata(id="20457e4f-d1de-4b92-ae69-142e27a4342a", name="Access of Stored Browser Credentials")],
    techniques=["T1539", "T1555"],
)
def main():
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands to aquire browser creds")
    cookie_path = f"{Path.home()}/Library/Application Support/Google/Chrome/Default/Cookies"
    _ = _common.execute_command([masquerade, cookie_path], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
