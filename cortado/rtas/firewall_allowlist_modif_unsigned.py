# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a0245bfc-d934-4b58-9a7c-a80eca05214b",
    name="firewall_allowlist_modif_unsigned",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="5c01669c-e1cc-4acc-95b6-8b5e4a92c970",
            name="Windows Firewall Exception List Modified via Untrusted Process",
        )
    ],
    techniques=["T1562"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    cmd = "netsh addallowedprogramENABLE"
    # Execute command
    _ = _common.execute_command([posh, "/c", cmd], timeout_secs=10)
    _common.remove_file(posh)
