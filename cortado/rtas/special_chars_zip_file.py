# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="dce9cb95-b97d-4874-ab7a-26382a1ba348",
    name="special_chars_zip_file",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="d22a85c6-d2ad-4cc4-bf7b-54787473669a", name="Potential Microsoft Office Sandbox Evasion")
    ],
    techniques=["T1497"],
)
def main():
    _common.log("Creating suspicious zip file with special characters to mimic evasion of sanboxed office apps.")
    _common.temporary_file_helper("testing", file_name="/tmp/~$test.zip")
