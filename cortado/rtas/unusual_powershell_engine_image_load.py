# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a5d82c62-6d4e-4d31-94f2-a996c9613604",
    name="unusual_powershell_engine_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f57505bb-a1d2-4d3b-b7b5-1d81d7bdb80e", name="Unusual PowerShell Engine ImageLoad")
    ],
    techniques=["T1059"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    posh = "C:\\Windows\\System32\\posh.exe"
    _common.copy_file(powershell, posh)

    log.info("Executing renamed powershell on system32 folder")
    _ = _common.execute_command([posh, "-c", "echo RTA"], timeout_secs=10)
    _common.remove_files([posh])
