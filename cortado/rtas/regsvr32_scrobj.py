# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="469c7bb5-44e2-4a85-b14d-5aee4f2b18c1",
    name="regsvr32_scrobj",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="0524c24c-e45e-4220-b21a-abdba0c46c4d", name="Regsvr32 Scriptlet Execution"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="5db08297-bf72-49f4-b426-f405c2b01326", name="Regsvr32 with Unusual Arguments"),
    ],
    techniques=["T1218", "T1036", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    regsvr32 = "C:\\Users\\Public\\regsvr32.exe"
    _common.copy_file(EXE_FILE, regsvr32)

    _ = _common.execute_command([regsvr32, "/c", "echo", "scrobj.exe /i:"], timeout_secs=10)
    _common.remove_files([regsvr32])
