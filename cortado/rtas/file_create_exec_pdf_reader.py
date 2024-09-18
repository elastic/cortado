# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="571e229f-fb92-48cf-b0fb-dd9630b1580f",
    name="file_create_exec_pdf_reader",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="1defdd62-cd8d-426e-a246-81a37751bb2b", name="Execution of File Written or Modified by PDF Reader"
        )
    ],
    techniques=["T1566", "T1566.001", "T1566.002"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    rdrcef = "C:\\Users\\Public\\rdrcef.exe"
    arp = "C:\\Users\\Public\\arp.exe"
    temp = "C:\\Users\\Public\\temp.exe"
    _common.copy_file(EXE_FILE, rdrcef)
    _common.copy_file(EXE_FILE, arp)

    # Execute command
    _ = _common.execute_command([rdrcef, "/c", "Copy-Item", arp, temp], timeout_secs=5)
    _ = _common.execute_command([temp], timeout_secs=5, kill=True)
    _common.remove_files([rdrcef, arp, temp])
