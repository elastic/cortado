# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9010739f-05c5-4fc0-b806-27753d3d6b5b",
    name="iterm2_autolaunch",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="7e52f64b-b0be-4437-81d1-91dd4dd5cb79", name="Potential iTerm2 Autolaunch Process Hijack")
    ],
)
def main():
    iterm2 = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
    backup_iterm2 = "/tmp/backup_iterm2"
    masquerade_bash = "/tmp/bash"
    path = Path(iterm2)
    restore_backup = False

    if path.is_file():
        restore_backup = True
        _common.copy_file(iterm2, backup_iterm2)

    _common.create_macos_masquerade(iterm2)
    _common.create_macos_masquerade(masquerade_bash)

    # Execute command
    log.info("Spawning bash from fake iterm2 commands")
    command = f"{masquerade_bash} /Users/test/.config/iterm2/AppSupport/Scripts/test"
    _ = _common.execute_command([iterm2, "childprocess", command], timeout_secs=10)

    # reset iterm2 and cleanup
    if restore_backup:
        _common.copy_file(backup_iterm2, iterm2)

    _common.remove_file(backup_iterm2)
    _common.remove_file(masquerade_bash)
