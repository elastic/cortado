# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="498c13e2-789c-4a6c-b32d-0589d2f907c2",
    name="msoffice_signed_binary_spawn",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="321e7877-075a-4582-8eff-777dde15e787", name="Signed Binary Execution via Microsoft Office"),
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
    ],
    techniques=["T1574", "T1218", "T1566"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    temposh = "C:\\Users\\Public\\posh.exe"
    binary = "C:\\Users\\Public\\winword.exe"
    _common.copy_file(powershell, binary)

    # Execute command
    log.info("Dropping executable using fake winword")
    _ = _common.execute_command([binary, "/c", f"Copy-Item {powershell} {temposh}"], timeout_secs=10)

    log.info("Executing it using fake winword")
    _ = _common.execute_command([binary, "/c", temposh])

    _common.remove_files([binary, temposh])
