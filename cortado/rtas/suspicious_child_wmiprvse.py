# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1f1833da-dca4-467c-9a9d-a61cf41d6b63",
    name="suspicious_child_wmiprvse",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="770e0c4d-b998-41e5-a62e-c7901fd7f470", name="Enumeration Command Spawned via WMIPrvSE")
    ],
    techniques=["T1047", "T1018", "T1087", "T1518"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    wmiprvse = "C:\\Users\\Public\\wmiprvse.exe"
    arp = "C:\\Windows\\System32\\arp.exe"
    _common.copy_file(EXE_FILE, wmiprvse)

    # Execute command
    _ = _common.execute_command([wmiprvse, "/c", arp], timeout_secs=2, kill=True)
    _common.remove_file(wmiprvse)
