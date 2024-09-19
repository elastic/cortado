# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="96c3cc10-7f86-428c-b353-e9de52472a96",
    name="auth_plugin",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="e6c98d38-633d-4b3e-9387-42112cd5ac10", name="Authorization Plugin Modification")],
    techniques=["T1547"],
)
def main():
    log.info("Executing file modification on test.plist to mimic authorization plugin modification")
    _common.create_file_with_data("/Library/Security/SecurityAgentPlugins/test.plist", "testing")
