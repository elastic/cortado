# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c01971a7-3aa6-4c43-aee6-85d48e93b8c1",
    name="persistence_terminal_plist_mod",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="2ac8ec88-8549-4fcb-9697-5f53e2f78bf4", name="Suspicious Terminal Plist Modification")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    log.info("Executing plutil commands to modify plist file.")
    plist = f"{Path.home()}/Library/Preferences/com.apple.Terminal.plist"
    _ = _common.execute_command(["plutil", "-convert", "xml1", plist])
    _ = _common.execute_command(["plutil", "-convert", "binary1", plist])
