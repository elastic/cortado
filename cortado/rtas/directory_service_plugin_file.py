# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ff744c89-20cb-4be0-9725-2430d0be7f6a",
    name="directory_service_plugin_file",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="89fa6cb7-6b53-4de2-b604-648488841ab8", name="Persistence via DirectoryService Plugin Modification"
        )
    ],
    techniques=["T1547"],
)
def main():
    log.info("Executing file modification on test.dsplug to mimic DirectoryService plugin modification")
    _common.create_file_with_data("/Library/DirectoryServices/PlugIns/test.dsplug", "testing")
