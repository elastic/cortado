# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4743705e-bf41-404a-b2f3-9f8f067516e6",
    name="dmg_create_in_tmp",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="fdb0e7ed-4210-4b71-be47-d0b0d9458fa7", name="Suspicious DMG File Creation in Temp Directory")
    ],
    techniques=["T1211", "T1059", "T1059.004"],
)
def main():
    tmp_dir = Path("/tmp/TestDMGDir")
    tmp_dmg = "/tmp/TestDMG.dmg"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    # Execute command
    log.info("Launching hdiutil commands to create a dmg in tmp directory")
    _ = _common.execute_command(["hdiutil", "create", "-size", "50m", "-volname", str(tmp_dir), "-ov", tmp_dmg])

    # cleanup
    _common.remove_directory(str(tmp_dir))
    _common.remove_file(tmp_dmg)
