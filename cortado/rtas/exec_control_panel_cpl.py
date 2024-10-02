# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ad9c9b24-cff3-4c4e-9fba-5c51ca9e58ae",
    name="exec_control_panel_cpl",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="a4862afb-1292-4f65-a15f-8d6a8019b5e2", name="Control Panel Process with Unusual Arguments")
    ],
    techniques=["T1218"],
)
def main():
    # Execute command
    log.info("Executing control.exe with a non-existing .cpl file")
    _ = _common.execute_command(["control.exe", "cpl1.cpl:../a"], timeout_secs=10)
