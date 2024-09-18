# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e85f7e39-da36-4ed4-be00-c5b29f4d763c",
    name="cron_tab_file_create",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="e5fc1285-d312-4b45-9e6b-e6c037276c17", name="Cron Tab Creation or Modification by an Unusual Process"
        )
    ],
    siem_rules=[],
    techniques=["T1053", "T1053.003"],
)
def main():
    log.info("Executing file creation on /private/var/at/tabs/test.")
    _common.create_file_with_data("/private/var/at/tabs/test", "testing")
