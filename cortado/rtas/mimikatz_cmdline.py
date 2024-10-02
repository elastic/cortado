# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="75fdde39-92bb-4a71-a4f1-f70e9c85d6db",
    name="mimikatz_cmdline",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="86bf5d50-7f5d-44b4-977b-dff222379727", name="Potential Credential Access via Mimikatz")
    ],
    techniques=["T1558", "T1003"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    log.info("Echoing a mimikatz command")
    _ = _common.execute_command([powershell, "echo", "misc::memssp"], timeout_secs=10)
