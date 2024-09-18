# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="3c8fc2cc-fa66-4c91-ae72-c72accaa92b7",
    name="login_window_plist",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="ac412404-57a5-476f-858f-4e8fbb4f48d8", name="Potential Persistence via Login Hook")],
    techniques=["T1547"],
)
def main():
    log.info("Executing deletion on /tmp/com.apple.loginwindow.plist file.")
    _common.create_file_with_data("/tmp/com.apple.loginwindow.plist", "testing")
