# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="8a6aee3d-fa5f-41ca-83f6-d0669fc159ac",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="57e9e13a-4eda-4b5f-b39a-d38c8104ab0f", name="Re-Opened Application Persistence")],
    siem_rules=[],
    techniques=[""],
)
def main():
    _common.log("Executing deletion on com.apple.loginwindow.test.plist file.")
    _common.temporary_file_helper("testing", file_name="com.apple.loginwindow.test.plist")
