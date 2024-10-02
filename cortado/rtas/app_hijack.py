# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9e87748e-9866-4b6b-832d-5cba4dda14e8",
    name="app_hijack",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="5d2c3833-a36a-483a-acea-5bf8cf363a81", name="Potential Default Application Hijacking")
    ],
    techniques=["T1574"],
)
def main():
    app_dir = Path("/Applications/test/Contents/")
    app_dir.mkdir(parents=True, exist_ok=True)
    masquerade = str(app_dir / "hijack")
    _common.create_macos_masquerade(masquerade)
    masquerade2 = "/tmp/open"
    _common.create_macos_masquerade(masquerade2)

    # Execute command
    log.info("Launching fake open commands to mimic hijacking applications")
    command = f"{masquerade2} -a /System/Applications/*"
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10)

    # cleanup
    _common.remove_directory(str(app_dir))
    _common.remove_file(masquerade2)
