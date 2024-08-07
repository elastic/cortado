# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="96c3cc10-7f86-428c-b353-e9de52472a96",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="e6c98d38-633d-4b3e-9387-42112cd5ac10", name="Authorization Plugin Modification")],
    techniques=["T1547"],
)
def main():
    _common.log("Executing file modification on test.plist to mimic authorization plugin modification")
    _common.temporary_file_helper("testing", file_name="/Library/Security/SecurityAgentPlugins/test.plist")
