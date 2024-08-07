# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="3c8fc2cc-fa66-4c91-ae72-c72accaa92b7",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="ac412404-57a5-476f-858f-4e8fbb4f48d8", name="Potential Persistence via Login Hook")],
    techniques=["T1547"],
)
def main():
    _common.log("Executing deletion on /tmp/com.apple.loginwindow.plist file.")
    _common.temporary_file_helper("testing", file_name="/tmp/com.apple.loginwindow.plist")


