# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1d452f81-8f5a-44a3-ae95-e95fe4bf2762",
    name="exec_cmd_attrib_hidden",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="4630d948-40d4-4cef-ac69-4002e29bc3db", name="Adding Hidden File Attribute via Attrib")
    ],
    techniques=["T1564", "T1564.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    attrib = "C:\\Users\\Public\\attrib.exe"
    _common.copy_file(EXE_FILE, attrib)

    # Execute command
    _ = _common.execute_command([attrib, "/c", "echo", "+h"], timeout_secs=10)
    _common.remove_file(attrib)
