# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="38c81994-958f-40c8-bb6a-20bc1b93d598",
    name="dock_plist",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="c81cefcb-82b9-4408-a533-3c3df549e62d", name="Persistence via Docker Shortcut Modification")
    ],
    techniques=["T1543"],
)
def main():
    log.info("Executing file modification on com.apple.dock.plist to mimic dock plist modification")
    _common.create_file_with_data(f"{Path.home()}/Library/Preferences/com.apple.dock.plist", "testing")
