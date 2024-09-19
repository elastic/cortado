# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="603d77bf-cdfc-44dd-94d3-5b4016caef94",
    name="keychain_cred_access",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="150f20b4-6b21-460b-8ae4-339695c1c86c", name="Suspicious Access to Keychain Credentials Files")
    ],
    siem_rules=[
        RuleMetadata(id="96e90768-c3b7-4df6-b5d9-6237f8bc36a8", name="Access to Keychain Credentials Directories")
    ],
    techniques=["T1555"],
)
def main():
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands to access keychain creds")
    _ = _common.execute_command([masquerade, f"{Path.home()}/Library/Keychains/test"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
