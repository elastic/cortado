# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="41c82553-01c2-41d6-a15d-3499fa99b4c0",
    name="werfault_masquerading",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="3d16f5f9-da4c-4b15-a501-505761b75ca6", name="Windows Error Manager/Reporting Masquerading")
    ],
    siem_rules=[],
    techniques=["T1055", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/regsvr32.exe")

    werfault = "C:\\Users\\Public\\werfault.exe"

    _common.copy_file(EXE_FILE, werfault)
    log.info("Making connection using fake werfault.exe")
    _ = _common.execute_command([werfault], timeout_secs=10)
    _common.remove_file(werfault)
