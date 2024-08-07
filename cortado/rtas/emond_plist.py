# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="2c186f11-d07c-4df6-8b86-bf9ffd6ca871",
    name="emond_plist",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="a6bf4dd4-743e-4da8-8c03-3ebd753a6c90", name="Emond Rules Creation or Modification")],
    techniques=["T1546"],
)
def main():
    _common.log("Executing file modification on test.plist to mimic emond file modification")
    _common.temporary_file_helper("testing", file_name="/private/etc/emond.d/rules/test.plist")
