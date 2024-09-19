# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8a6aee3d-fa5f-41ca-83f6-d0669fc159ac",
    name="persistence_reopened_app",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="57e9e13a-4eda-4b5f-b39a-d38c8104ab0f", name="Re-Opened Application Persistence")],
    siem_rules=[],
    techniques=[""],
)
def main():
    log.info("Executing deletion on com.apple.loginwindow.test.plist file.")
    _common.create_file_with_data("com.apple.loginwindow.test.plist", "testing")
